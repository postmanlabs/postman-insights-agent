package trace

import (
	"math"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/OneOfOne/xxhash"
	"github.com/pkg/errors"
	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/client_telemetry"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/util"
	"github.com/spf13/viper"
)

type SuccessTelemetry struct {
	Channel chan struct{}
	Once    sync.Once
}

// UploadStatus is a bounded classification of a witness-report upload outcome.
// The set is closed on purpose: it is reported as a telemetry dimension, so an
// open-ended string would let backend error text drive cardinality.
type UploadStatus string

const (
	UploadSuccess      UploadStatus = "success"
	UploadThrottled    UploadStatus = "throttled"
	UploadClientError  UploadStatus = "client_error"
	UploadServerError  UploadStatus = "server_error"
	UploadNetworkError UploadStatus = "network_error"
)

// ClassifyUploadError maps an upload error to an UploadStatus. It reports the
// class only; the error text is never propagated to telemetry.
func ClassifyUploadError(err error) UploadStatus {
	if err == nil {
		return UploadSuccess
	}

	var httpErr rest.HTTPError
	if errors.As(err, &httpErr) {
		switch {
		case httpErr.StatusCode == http.StatusTooManyRequests:
			return UploadThrottled
		case httpErr.StatusCode >= 500:
			return UploadServerError
		case httpErr.StatusCode >= 400:
			return UploadClientError
		}
	}
	return UploadNetworkError
}

// UploadReporter receives the outcome of each witness-report upload attempt. It
// is called once per upload batch (not per witness), so a plain lock is fine.
type UploadReporter interface {
	RecordUpload(at time.Time, status UploadStatus)
}

type Collector interface {
	// Hands new data from network to the collector. The implementation may choose
	// to process them asynchronously (e.g. to wait for the response to a
	// corresponding request).
	// Implementations should only return error if the error is unrecoverable and
	// the whole process should stop immediately.
	Process(akinet.ParsedNetworkTraffic) error

	// Implementations must complete processing all requests/responses before
	// returning.
	Close() error
}

// Wraps a Collector and performs sampling.
type SamplingCollector struct {
	// A sample is used if a coin flip is below this threshold.
	sampleThreshold float64

	collector Collector
}

// Wraps a collector and performs sampling. Returns the collector itself if the
// given sampleRate is 1.0.
func NewSamplingCollector(sampleRate float64, collector Collector) Collector {
	if sampleRate == 1.0 {
		return collector
	}

	return &SamplingCollector{
		sampleThreshold: float64(math.MaxUint32) * sampleRate,
		collector:       collector,
	}
}

// Sample based on stream ID and seq so a pair of request and response are
// either both selected or both excluded.
func (sc *SamplingCollector) includeSample(key string) bool {
	h := xxhash.New32()
	h.WriteString(key)
	return float64(h.Sum32()) < sc.sampleThreshold
}

func (sc *SamplingCollector) Process(t akinet.ParsedNetworkTraffic) error {
	var key string
	switch c := t.Content.(type) {
	case akinet.HTTPRequest:
		key = c.StreamID.String() + strconv.Itoa(c.Seq)
	case akinet.HTTPResponse:
		key = c.StreamID.String() + strconv.Itoa(c.Seq)
	case akinet.TCPConnectionMetadata:
		key = akid.String(c.ConnectionID)
	case akinet.TLSHandshakeMetadata:
		key = akid.String(c.ConnectionID)
	default:
		key = ""
	}
	if sc.includeSample(key) {
		return sc.collector.Process(t)
	}
	return nil
}

func (sc *SamplingCollector) Close() error {
	return sc.collector.Close()
}

type UserTrafficCollector struct {
	Collector          Collector
	DropDogfoodTraffic bool // Filters out CLI's own traffic to Akita APIs.
	DropNginxTraffic   bool // Filters out traffic to/from the nginx.
}

func (sc *UserTrafficCollector) Process(t akinet.ParsedNetworkTraffic) error {
	if sc.DropDogfoodTraffic && util.ContainsCLITraffic(t) {
		return nil
	}

	if sc.DropNginxTraffic && util.ContainsNginxTraffic(t) {
		return nil
	}

	return sc.Collector.Process(t)
}

func (sc *UserTrafficCollector) Close() error {
	return sc.Collector.Close()
}

// This is a shim to add packet counts based on payload type.
type PacketCountCollector struct {
	PacketCounts     PacketCountConsumer
	Collector        Collector
	SuccessTelemetry *SuccessTelemetry

	// RecordHTTPMessage, if set, is called for every HTTP request or response
	// that reaches this collector. It exists so a supervising process can tell
	// whether a capture target is producing usable traffic; it is not a packet
	// counter (PacketCounts already serves that purpose).
	//
	// It runs on the capture path for every message, so implementations must not
	// block, allocate, or take a lock. An atomic store is the intended shape.
	//
	// Note that this collector sits inside sampling, rate limiting, and the
	// host/path filters, so this reports traffic that survived admission rather
	// than traffic that arrived at the interface.
	RecordHTTPMessage func(observedAt time.Time)
}

// Don't record self-generated traffic in the breakdown by hostname,
// unless the --dogfood flag has been set.
func (pc *PacketCountCollector) IncludeHostName(tlsName string) bool {
	if tlsName == rest.Domain {
		return viper.GetBool("dogfood")
	}
	return true
}

func (pc *PacketCountCollector) Process(t akinet.ParsedNetworkTraffic) error {
	switch c := t.Content.(type) {
	case akinet.HTTPRequest:
		pc.recordHTTPMessage(t)
		pc.PacketCounts.Update(client_telemetry.PacketCounts{
			Interface:     t.Interface,
			DstHost:       c.Host,
			SrcPort:       t.SrcPort,
			DstPort:       t.DstPort,
			HTTPRequests:  boolToInt(!isTLS(t)),
			HTTPSRequests: boolToInt(isTLS(t)),
		})
	case akinet.HTTPResponse:
		// TODO(cns): There's no easy way to get the host here to count HTTP
		//    responses.  Revisit this if we ever add a pass to pair HTTP
		//    requests and responses independently of the backend collector.
		pc.recordHTTPMessage(t)
		pc.PacketCounts.Update(client_telemetry.PacketCounts{
			Interface:      t.Interface,
			SrcPort:        t.SrcPort,
			DstPort:        t.DstPort,
			HTTPResponses:  boolToInt(!isTLS(t)),
			HTTPSResponses: boolToInt(isTLS(t)),
		})
	case akinet.TLSClientHello:
		dstHost := HostnameUnavailable
		if c.Hostname != nil {
			dstHost = *c.Hostname
		}

		if pc.IncludeHostName(dstHost) {
			pc.PacketCounts.Update(client_telemetry.PacketCounts{
				Interface: t.Interface,
				DstHost:   dstHost,
				SrcPort:   t.SrcPort,
				DstPort:   t.DstPort,
				TLSHello:  1,
			})
		}
	case akinet.TLSServerHello:
		// Ideally, we would pick the DNS name the client used in the
		// Client Hello, but we don't pair those messages.  Barring that, any
		// of the DNS names will serve as a reasonable identifier.  Pick the
		// largest, which avoids "*" prefixes when possible.
		dstHost := HostnameUnavailable
		if 0 < len(c.DNSNames) {
			sort.Strings(c.DNSNames)
			dstHost = c.DNSNames[len(c.DNSNames)-1]
		}

		if pc.IncludeHostName(dstHost) {
			pc.PacketCounts.Update(client_telemetry.PacketCounts{
				Interface: t.Interface,
				DstHost:   dstHost,
				SrcPort:   t.SrcPort,
				DstPort:   t.DstPort,
				TLSHello:  1,
			})
		}
	case akinet.TCPPacketMetadata, akinet.TCPConnectionMetadata:
		// Don't count TCP metadata.
	case akinet.TLSHandshakeMetadata:
		// Don't count TLS metadata.
	case akinet.HTTP2ConnectionPreface:
		pc.PacketCounts.Update(client_telemetry.PacketCounts{
			Interface:     t.Interface,
			SrcPort:       t.SrcPort,
			DstPort:       t.DstPort,
			HTTP2Prefaces: 1,
		})
	case akinet.QUICHandshakeMetadata:
		pc.PacketCounts.Update(client_telemetry.PacketCounts{
			Interface:      t.Interface,
			SrcPort:        t.SrcPort,
			DstPort:        t.DstPort,
			QUICHandshakes: 1,
		})
	default:
		pc.PacketCounts.Update(client_telemetry.PacketCounts{
			Interface: t.Interface,
			SrcPort:   t.SrcPort,
			DstPort:   t.DstPort,
			Unparsed:  1,
		})
	}
	if pc.PacketCounts.HasRequestAndResponse() {
		pc.SendSuccessTelemetry()
	}
	return pc.Collector.Process(t)
}

// recordHTTPMessage reports capture liveness for one HTTP message. Deliberately
// not tied to the downstream Process result: the sink returns nil for traffic it
// could not parse, so a nil error is not evidence that anything was processed.
func (pc *PacketCountCollector) recordHTTPMessage(t akinet.ParsedNetworkTraffic) {
	if pc.RecordHTTPMessage == nil {
		return
	}
	observedAt := t.ObservationTime
	if observedAt.IsZero() {
		observedAt = time.Now()
	}
	pc.RecordHTTPMessage(observedAt)
}

func (pc *PacketCountCollector) SendSuccessTelemetry() {
	if pc.SuccessTelemetry == nil {
		return
	}
	pc.SuccessTelemetry.Once.Do(func() {
		pc.SuccessTelemetry.Channel <- struct{}{}
	})
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func isTLS(t akinet.ParsedNetworkTraffic) bool {
	return t.TransportSecurity == akinet.TransportSecurityTLS
}

func (pc *PacketCountCollector) Close() error {
	return pc.Collector.Close()
}
