package trace

import (
	"context"
	"net/http"
	"time"

	pb "github.com/akitasoftware/akita-ir/go/api_spec"
	kgxapi "github.com/akitasoftware/akita-libs/api_schema"
	"github.com/akitasoftware/akita-libs/batcher"
	"github.com/akitasoftware/akita-libs/client_telemetry"
	"github.com/akitasoftware/go-utils/optionals"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
)

// A report that hasn't yet been processed for upload.
type rawReport struct {
	Witness            *witnessWithInfo
	TCPReport          *kgxapi.TCPConnectionReport
	TLSHandshakeReport *kgxapi.TLSHandshakeReport
}

type reportBuffer struct {
	collector          *BackendCollector
	uploadReports      chan *kgxapi.UploadReportsRequest
	activeUploadReport *kgxapi.UploadReportsRequest

	packetCounts         PacketCountConsumer
	maxSize_bytes        int
	maxWitnessSize_bytes optionals.Optional[int]

	// If true, indicates that witnesses sent to this buffer will have intact
	// payloads. If false, indicates that witnesses will have their payloads
	// obfuscated before being sent to this buffer.
	witnessesHavePayloads bool
}

var _ batcher.Buffer[rawReport] = (*reportBuffer)(nil)

func newReportBuffer(
	collector *BackendCollector,
	packetCounts PacketCountConsumer,
	maxSize_bytes int,
	maxWitnessSize_bytes optionals.Optional[int],
	witnessesHavePayloads bool,
	reportBuffers int,
) *reportBuffer {
	uploadReports := make(chan *kgxapi.UploadReportsRequest, reportBuffers)
	for range reportBuffers {
		uploadReports <- &kgxapi.UploadReportsRequest{}
	}
	activeUploadReport := <-uploadReports

	return &reportBuffer{
		collector:             collector,
		uploadReports:         uploadReports,
		activeUploadReport:    activeUploadReport,
		packetCounts:          packetCounts,
		maxSize_bytes:         maxSize_bytes,
		maxWitnessSize_bytes:  maxWitnessSize_bytes,
		witnessesHavePayloads: witnessesHavePayloads,
	}
}

func (buf *reportBuffer) Add(raw rawReport) (bool, error) {
	if raw.Witness != nil {
		buf.addWitness(raw.Witness)
	}

	if raw.TCPReport != nil {
		buf.activeUploadReport.AddTCPConnectionReport(raw.TCPReport)
	}

	if raw.TLSHandshakeReport != nil {
		buf.activeUploadReport.AddTLSHandshakeReport(raw.TLSHandshakeReport)
	}

	return buf.isFull(), nil
}

// Adds the given witness to the buffer. If the witness is too large, it is
// obfuscated. If it is still too large after obfuscation, it is dropped. Any
// errors that occur are logged.
func (buf *reportBuffer) addWitness(w *witnessWithInfo) {
	witnessReport, err := w.toReport()
	if err != nil {
		printer.Warningf("Failed to convert witness to report: %v\n", err)
		return
	}

	if buf.witnessesHavePayloads {
		if maxSize, exists := buf.maxWitnessSize_bytes.Get(); exists && len(witnessReport.WitnessProto) > maxSize {
			if w.witness.GetMethod().GetMeta().GetHttp().Obfuscation != pb.HTTPMethodMeta_ZERO_VALUE {
				// The witness exceeds our per-witness storage limit. Obfuscate it to
				// reduce its size while retaining its typing information.
				printer.Debugf("Obfuscating oversized witness (%d MB) captured on interface %s\n", len(witnessReport.WitnessProto)/1_000_000, w.netInterface)
				buf.collector.redactor.ZeroAllPrimitives(w.witness.GetMethod())
			}
			witnessReport, err = w.toReport()
			if err != nil {
				printer.Warningf("Failed to convert obfuscated witness to report: %v\n", err)
				return
			}
		}
	}

	if maxSize, exists := buf.maxWitnessSize_bytes.Get(); exists && len(witnessReport.WitnessProto) > maxSize {
		// The witness is still too large. Drop it.
		printer.Debugf("Dropping oversized obfuscated witness (%d MB) captured on interface %s\n", len(witnessReport.WitnessProto)/1_000_000, w.netInterface)

		buf.packetCounts.Update(client_telemetry.PacketCounts{
			Interface:          w.netInterface,
			SrcPort:            int(w.srcPort),
			DstPort:            int(w.dstPort),
			OversizedWitnesses: 1,
		})
		return
	}

	buf.activeUploadReport.AddWitnessReport(witnessReport)
}

func (buf *reportBuffer) Flush() error {
	if buf.activeUploadReport.IsEmpty() {
		return nil
	}

	// Cache current active upload report and reset it to next report.
	// If witness rate is very high, reading from the channel could still block.
	report := buf.activeUploadReport
	learnSessions := buf.collector.getLearnSession()
	go func() {
		// Upload to the back end.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		err := buf.collector.learnClient.AsyncReportsUpload(ctx, learnSessions, report)
		if err != nil {
			switch e := err.(type) {
			case rest.HTTPError:
				if e.StatusCode == http.StatusTooManyRequests {
					// XXX Not all commands that call into this code have a --rate-limit
					// option.
					err = errors.Wrap(err, "your witness uploads are being throttled. Postman Insights will generate partial results. Try reducing the --rate-limit value to avoid this.")
				}
			}

			printer.Warningf("Failed to upload to Postman: %v\n", err)
		}
		printer.Debugf("Uploaded %d witnesses, %d TCP connection reports, and %d TLS handshake reports\n", len(report.Witnesses), len(report.TCPConnections), len(report.TLSHandshakes))

		// Ensure the buffer is empty when we return.
		report.Clear()
		buf.uploadReports <- report
	}()
	buf.activeUploadReport = <-buf.uploadReports

	return nil
}

// Determines whether the buffer is at or beyond capacity.
func (buf *reportBuffer) isFull() bool {
	return buf.activeUploadReport.SizeInBytes() >= buf.maxSize_bytes
}
