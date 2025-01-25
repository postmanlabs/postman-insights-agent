package trace

import (
	"encoding/base64"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	pb "github.com/akitasoftware/akita-ir/go/api_spec"
	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/akinet"
	kgxapi "github.com/akitasoftware/akita-libs/api_schema"
	"github.com/akitasoftware/akita-libs/batcher"
	"github.com/akitasoftware/akita-libs/http_rest_methods"
	"github.com/akitasoftware/akita-libs/spec_util"
	"github.com/akitasoftware/akita-libs/spec_util/ir_hash"
	"github.com/akitasoftware/go-utils/optionals"
	"github.com/akitasoftware/go-utils/sets"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/data_masks"
	"github.com/postmanlabs/postman-insights-agent/learn"
	"github.com/postmanlabs/postman-insights-agent/plugin"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
)

const (
	// We stop trying to pair partial witnesses older than pairCacheExpiration.
	pairCacheExpiration = time.Minute

	// How often we clean out stale partial witnesses from pairCache.
	pairCacheCleanupInterval = 30 * time.Second

	// Max size per upload batch.
	uploadBatchMaxSize_bytes = 60_000_000 // 60 MB

	// How often to flush the upload batch.
	uploadBatchFlushDuration = 30 * time.Second
)

type witnessWithInfo struct {
	// The name of the interface on which this witness was captured.
	netInterface string

	srcIP           net.IP // The HTTP client's IP address.
	srcPort         uint16 // The HTTP client's port number.
	dstIP           net.IP // The HTTP server's IP address.
	dstPort         uint16 // The HTTP server's port number.
	observationTime time.Time
	id              akid.WitnessID
	requestEnd      time.Time
	responseStart   time.Time

	// Mutex protecting witness while it is being processed and/or flushed.
	witnessMutex sync.Mutex

	// Whether the witness has been flushed to the backend.
	witnessFlushed bool

	witness *pb.Witness
}

func (r *witnessWithInfo) toReport() (*kgxapi.WitnessReport, error) {
	// Hash algorithm defined in
	// https://docs.google.com/document/d/1ZANeoLTnsO10DcuzsAt6PBCt2MWLYW8oeu_A6d9bTJk/edit#heading=h.tbvm9waph6eu
	hash := ir_hash.HashWitnessToString(r.witness)

	b, err := proto.Marshal(r.witness)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal witness proto")
	}

	return &kgxapi.WitnessReport{
		Direction:       kgxapi.Inbound,
		OriginAddr:      r.srcIP,
		OriginPort:      r.srcPort,
		DestinationAddr: r.dstIP,
		DestinationPort: r.dstPort,

		WitnessProto:      base64.URLEncoding.EncodeToString(b),
		ClientWitnessTime: r.observationTime,
		Hash:              hash,
		ID:                r.id,
	}, nil
}

func (w *witnessWithInfo) recordTimestamp(isRequest bool, t akinet.ParsedNetworkTraffic) {
	if isRequest {
		w.requestEnd = t.FinalPacketTime
	} else {
		w.responseStart = t.ObservationTime
	}

}

func (w *witnessWithInfo) computeProcessingLatency(isRequest bool, t akinet.ParsedNetworkTraffic) {
	// Processing latency is the time from the last packet of the request,
	// to the first packet of the response.
	requestEnd := w.requestEnd
	responseStart := t.ObservationTime

	// handle arrival in opposite order
	if isRequest {
		requestEnd = t.FinalPacketTime
		responseStart = w.responseStart
	}

	// Missing data, leave as default value in protobuf
	if requestEnd.IsZero() || responseStart.IsZero() {
		return
	}

	// HTTPMethodMetadata only for now
	if meta := spec_util.HTTPMetaFromMethod(w.witness.Method); meta != nil {
		latency := responseStart.Sub(requestEnd)
		meta.ProcessingLatency = float32(latency.Microseconds()) / 1000.0
	}
}

// An additional method supported by the backend collector to switch learn
// sessions.
type LearnSessionCollector interface {
	Collector

	SwitchLearnSession(akid.LearnSessionID)
}

// Sends witnesses up to akita cloud.
type BackendCollector struct {
	serviceID      akid.ServiceID
	learnSessionID akid.LearnSessionID
	learnClient    rest.LearnClient

	// Cache un-paired partial witnesses by pair key.
	// akid.WitnessID -> *witnessWithInfo
	pairCache sync.Map

	// Batch of reports (witnesses, TCP-connection reports, etc.) pending upload.
	uploadReportBatch *batcher.InMemory[rawReport]

	// Channel controlling periodic cache flush
	flushDone chan struct{}

	// Mutex protecting learnSessionID
	learnSessionMutex sync.Mutex

	// Whether to keep witness payloads intact. If false, witness payloads will be
	// obfuscated before being sent to the back end.
	sendWitnessPayloads bool

	plugins []plugin.AkitaPlugin

	redactor *data_masks.Redactor
}

var _ LearnSessionCollector = (*BackendCollector)(nil)

func NewBackendCollector(
	svc akid.ServiceID,
	lrn akid.LearnSessionID,
	lc rest.LearnClient,
	maxWitnessSize_bytes optionals.Optional[int],
	packetCounts PacketCountConsumer,
	sendWitnessPayloads bool,
	plugins []plugin.AkitaPlugin,
) (Collector, error) {
	redactor, err := data_masks.NewRedactor(svc, lc)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to instantiate redactor for %s", svc)
	}
	col := &BackendCollector{
		serviceID:           svc,
		learnSessionID:      lrn,
		learnClient:         lc,
		flushDone:           make(chan struct{}),
		plugins:             plugins,
		sendWitnessPayloads: sendWitnessPayloads,
		redactor:            redactor,
	}

	col.uploadReportBatch = batcher.NewInMemory[rawReport](
		newReportBuffer(col, packetCounts, uploadBatchMaxSize_bytes, maxWitnessSize_bytes, sendWitnessPayloads),
		uploadBatchFlushDuration,
	)

	go col.periodicFlush()

	return col, nil
}

func (c *BackendCollector) Process(t akinet.ParsedNetworkTraffic) error {
	var isRequest bool
	var partial *learn.PartialWitness
	var parseHTTPErr error
	switch content := t.Content.(type) {
	case akinet.HTTPRequest:
		isRequest = true
		partial, parseHTTPErr = learn.ParseHTTP(content)
	case akinet.HTTPResponse:
		partial, parseHTTPErr = learn.ParseHTTP(content)
	case akinet.TCPConnectionMetadata:
		return c.processTCPConnection(t, content)
	case akinet.TLSHandshakeMetadata:
		return c.processTLSHandshake(content)
	default:
		// Non-HTTP traffic not handled
		return nil
	}

	if parseHTTPErr != nil {
		telemetry.RateLimitError("parse HTTP", parseHTTPErr)
		printer.Debugf("Failed to parse HTTP, skipping: %v\n", parseHTTPErr)
		return nil
	}

	if val, ok := c.pairCache.LoadAndDelete(partial.PairKey); ok {
		pair := val.(*witnessWithInfo)

		func() {
			// Lock the witness while it is being processed and flushed
			// and unlock it after it is flushed
			pair.witnessMutex.Lock()
			defer pair.witnessMutex.Unlock()

			// Combine the pair, merging the result into the existing item
			// rather than the new partial.
			learn.MergeWitness(pair.witness, partial.Witness)
			pair.computeProcessingLatency(isRequest, t)

			// If partial is the request, flip the src/dst in the pair before
			// reporting.
			if isRequest {
				pair.srcIP, pair.dstIP = pair.dstIP, pair.srcIP
				pair.srcPort, pair.dstPort = pair.dstPort, pair.srcPort
			}

			c.queueUpload(pair)
			printer.Debugf("Completed witness %v at %v -- %v\n",
				partial.PairKey, t.ObservationTime, t.FinalPacketTime)
		}()
	} else {
		// Store the partial witness for now, waiting for its pair or a
		// flush timeout.
		w := &witnessWithInfo{
			netInterface:    t.Interface,
			srcIP:           t.SrcIP,
			srcPort:         uint16(t.SrcPort),
			dstIP:           t.DstIP,
			dstPort:         uint16(t.DstPort),
			witness:         partial.Witness,
			observationTime: t.ObservationTime,
			id:              partial.PairKey,
		}
		// Store whichever timestamp brackets the processing interval.
		w.recordTimestamp(isRequest, t)
		c.pairCache.Store(partial.PairKey, w)
		printer.Debugf("Partial witness %v request=%v at %v -- %v\n",
			partial.PairKey, isRequest, t.ObservationTime, t.FinalPacketTime)

	}
	return nil
}

func (c *BackendCollector) processTCPConnection(packet akinet.ParsedNetworkTraffic, tcp akinet.TCPConnectionMetadata) error {
	srcAddr, srcPort, dstAddr, dstPort := packet.SrcIP, packet.SrcPort, packet.DstIP, packet.DstPort
	if tcp.Initiator == akinet.DestInitiator {
		srcAddr, srcPort, dstAddr, dstPort = dstAddr, dstPort, srcAddr, srcPort
	}

	c.uploadReportBatch.Add(rawReport{
		TCPReport: &kgxapi.TCPConnectionReport{
			ID:             tcp.ConnectionID,
			SrcAddr:        srcAddr,
			SrcPort:        uint16(srcPort),
			DestAddr:       dstAddr,
			DestPort:       uint16(dstPort),
			FirstObserved:  packet.ObservationTime,
			LastObserved:   packet.FinalPacketTime,
			InitiatorKnown: tcp.Initiator != akinet.UnknownTCPConnectionInitiator,
			EndState:       tcp.EndState,
		},
	})
	return nil
}

func (c *BackendCollector) processTLSHandshake(tls akinet.TLSHandshakeMetadata) error {
	c.uploadReportBatch.Add(rawReport{
		TLSHandshakeReport: &kgxapi.TLSHandshakeReport{
			ID:                      tls.ConnectionID,
			Version:                 tls.Version,
			SNIHostname:             tls.SNIHostname,
			SupportedProtocols:      tls.SupportedProtocols,
			SelectedProtocol:        tls.SelectedProtocol,
			SubjectAlternativeNames: tls.SubjectAlternativeNames,
		},
	})
	return nil
}

var cloudAPIEnvironmentsPathRE = regexp.MustCompile(`^/environments/[^/]+$`)
var cloudAPIHostnames = sets.NewSet[string]()

func init() {
	cloudAPIHostnames.Insert("api.getpostman-stage.com")
	cloudAPIHostnames.Insert("api.getpostman.com")
	cloudAPIHostnames.Insert("api.postman.com")
	cloudAPIHostnamesEnv := os.Getenv("XXX_INSIGHTS_AGENT_CLOUD_API_HOSTNAMES")
	for _, hostname := range strings.Split(cloudAPIHostnamesEnv, " ") {
		cloudAPIHostnames.Insert(strings.ToLower(hostname))
	}
}

// Returns true if the witness should be excluded from Repro Mode.
//
// XXX This is a stop-gap hack to exclude certain endpoints for Cloud API from
// Repro Mode.
func excludeWitnessFromReproMode(w *pb.Witness) bool {

	httpMeta := w.GetMethod().GetMeta().GetHttp()
	if httpMeta == nil {
		return false
	}

	if cloudAPIHostnames.Contains(strings.ToLower(httpMeta.Host)) {
		switch httpMeta.Method {
		case http_rest_methods.GET.String():
			// Exclude GET /environments/{environment}.
			if cloudAPIEnvironmentsPathRE.MatchString(httpMeta.PathTemplate) {
				return true
			}

		case http_rest_methods.POST.String():
			// Exclude POST /environments.
			if httpMeta.PathTemplate == "/environments" {
				return true
			}

		case http_rest_methods.PUT.String():
			// Exclude PUT /environments/{environment}.
			// Exclude GET /environments/{environment}.
			if cloudAPIEnvironmentsPathRE.MatchString(httpMeta.PathTemplate) {
				return true
			}
		}
	}
	return false
}

func (c *BackendCollector) queueUpload(w *witnessWithInfo) {
	if w.witnessFlushed {
		printer.Debugf("Witness %v already flushed.\n", w.id)
		return
	}
	defer func() {
		w.witnessFlushed = true
	}()

	// Mark the method as not obfuscated.
	w.witness.GetMethod().GetMeta().GetHttp().Obfuscation = pb.HTTPMethodMeta_NONE

	for _, p := range c.plugins {
		if err := p.Transform(w.witness.GetMethod()); err != nil {
			// Only upload if plugins did not return error.
			printer.Errorf("plugin %q returned error, skipping: %v", p.Name(), err)
			return
		}
	}

	if !c.sendWitnessPayloads ||
		!hasOnlyErrorResponses(w.witness.GetMethod()) ||
		excludeWitnessFromReproMode(w.witness) {
		// Obfuscate the original value so type inference engine can use it on the
		// backend without revealing the actual value.
		data_masks.ObfuscateMethod(w.witness.GetMethod())
	} else {
		c.redactor.RedactSensitiveData(w.witness.GetMethod())
	}

	c.uploadReportBatch.Add(rawReport{
		Witness: w,
	})
}

func (c *BackendCollector) Close() error {
	defer c.redactor.StopPeriodicUpdates()
	close(c.flushDone)
	c.flushPairCache(time.Now())
	c.uploadReportBatch.Close()
	return nil
}

func (c *BackendCollector) SwitchLearnSession(session akid.LearnSessionID) {
	c.learnSessionMutex.Lock()
	defer c.learnSessionMutex.Unlock()
	c.learnSessionID = session
}

func (c *BackendCollector) getLearnSession() akid.LearnSessionID {
	c.learnSessionMutex.Lock()
	defer c.learnSessionMutex.Unlock()
	return c.learnSessionID
}

func (c *BackendCollector) periodicFlush() {
	ticker := time.NewTicker(pairCacheCleanupInterval)

	for {
		select {
		case <-ticker.C:
			c.flushPairCache(time.Now().Add(-1 * pairCacheExpiration))
		case <-c.flushDone:
			ticker.Stop()
			return
		}
	}
}

func (c *BackendCollector) flushPairCache(cutoffTime time.Time) {
	c.pairCache.Range(func(k, v interface{}) bool {
		e := v.(*witnessWithInfo)
		if e.observationTime.Before(cutoffTime) {
			// Lock the witness while it is being flushed
			// and unlock it after it is deleted from pairCache
			e.witnessMutex.Lock()
			defer e.witnessMutex.Unlock()

			c.queueUpload(e)
			c.pairCache.Delete(k)
		}
		return true
	})
}
