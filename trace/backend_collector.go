package trace

import (
	"encoding/base64"
	"encoding/json"
	"io"
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
	"github.com/akitasoftware/akita-libs/spec_util"
	"github.com/akitasoftware/akita-libs/spec_util/ir_hash"
	"github.com/akitasoftware/akita-libs/tags"
	"github.com/akitasoftware/go-utils/optionals"
	"github.com/akitasoftware/go-utils/sets"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/capturestats"
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
	pairCacheCleanupInterval = 5 * time.Second

	// Max size per upload batch.
	uploadBatchMaxSize_bytes = 30_000_000 // 30 MB

	// How often to flush the upload batch.
	uploadBatchFlushDuration = 5 * time.Second
)

type witnessWithInfo struct {
	// The name of the interface on which this witness was captured.
	netInterface string

	srcIP           net.IP // The HTTP client's IP address.
	srcPort         uint16 // The HTTP client's port number.
	dstIP           net.IP // The HTTP server's IP address.
	dstPort         uint16 // The HTTP server's port number.
	observationTime time.Time
	finalPacketTime time.Time
	id              akid.WitnessID
	isRequest       bool

	// The TCP stream this half arrived on. Retained because id (the pair key)
	// cannot supply it: learn.ToWitnessID hashes "<streamID>:<seq>" through a
	// v5 UUID, which is one-way. Without this field an expired witness has
	// only its address 4-tuple, and an address pair can be reused by a later
	// connection while a stream cannot -- so keeping the stream is what lets
	// pair-expiry attribution share a key space with the rate-limit
	// collector's per-stream view of rejected responses.
	streamID uuid.UUID

	// direction is the traffic direction relative to the monitored service, as
	// reported by the capture layer (currently the eBPF path; DirectionUnknown
	// for producers that do not compute it, e.g. pcap).
	direction akinet.NetTrafficDirection

	// Mutex protecting witness while it is being processed and/or flushed.
	witnessMutex sync.Mutex

	// Whether the witness has been flushed to the backend.
	witnessFlushed bool

	witness *pb.Witness

	telemetryEventReporter func(string)
}

func (r *witnessWithInfo) toReport() (*kgxapi.WitnessReport, error) {
	// Hash algorithm defined in
	// https://docs.google.com/document/d/1ZANeoLTnsO10DcuzsAt6PBCt2MWLYW8oeu_A6d9bTJk/edit#heading=h.tbvm9waph6eu
	hash := ir_hash.HashWitnessToString(r.witness)

	b, err := proto.Marshal(r.witness)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal witness proto")
	}

	// Map the capture-layer direction to the backend's NetworkDirection.
	// Default to Inbound when unknown, preserving prior behaviour for producers
	// (e.g. the pcap path) that do not yet compute a direction.
	direction := kgxapi.Inbound
	if r.direction == akinet.DirectionOutbound {
		direction = kgxapi.Outbound
	}

	return &kgxapi.WitnessReport{
		Direction:       direction,
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

func (w *witnessWithInfo) computeProcessingLatency(stats *capturestats.Stats, isRequest bool, t akinet.ParsedNetworkTraffic) {
	if w.isRequest == isRequest {
		stats.IncrSameDirectionMerges()
		if isRequest {
			printer.Debugln("Skipping latency calculation. Matched 2 requests together.")
		} else {
			printer.Debugln("Skipping latency calculation. Matched 2 responses together.")
		}
		w.reportTelemetryEvent("latency_anomaly_mismatched_pair_type")
		return
	}

	// Processing latency is the time from the last packet of the request,
	// to the first packet of the response.
	var requestEnd, responseStart time.Time
	if w.isRequest {
		requestEnd = w.finalPacketTime
		responseStart = t.ObservationTime
	} else {
		requestEnd = t.FinalPacketTime
		responseStart = w.observationTime
	}

	// Missing data, leave as default value in protobuf
	if requestEnd.IsZero() || responseStart.IsZero() {
		printer.Debugf("Skipping latency calculation. Zero value timestamps. RequestEnd: %v ResponseStart %v.\n", requestEnd, responseStart)
		return
	}

	latency := float32(responseStart.Sub(requestEnd).Microseconds()) / 1000.0
	if latency < 0.0 {
		stats.RecordNegativeLatency(latency)
		printer.Debugf("Negative latency calculation: %v\n", latency)
		w.reportTelemetryEvent("latency_anomaly_negative_latency")
	}

	// HTTPMethodMetadata only for now
	if meta := spec_util.HTTPMetaFromMethod(w.witness.Method); meta != nil {
		meta.ProcessingLatency = latency
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
	traceTags      map[tags.Key]string
	learnSessionID akid.LearnSessionID
	learnClient    rest.LearnClient

	// Cache un-paired partial witnesses by pair key.
	// akid.WitnessID -> *witnessWithInfo
	pairCache sync.Map

	// Batch of reports (witnesses, TCP-connection reports, etc.) pending upload.
	uploadReportBatch *batcher.InMemory[rawReport]
	reportBuffer      *reportBuffer

	// Optional observer of upload outcomes. Set via SetUploadReporter rather than
	// passed to the constructor, which already takes more arguments than is
	// comfortable. Guarded by uploadReporterMutex because Flush runs the upload
	// in its own goroutine.
	uploadReporter         UploadReporter
	uploadReporterMutex    sync.Mutex
	telemetryReporter      func(string)
	telemetryCountReporter func(string, uint64)
	telemetryReporterMutex sync.Mutex

	// Channel controlling periodic cache flush
	flushDone chan struct{}

	// Answers "was a message on this stream already discarded as unmatched"
	// for witnesses that expire unpaired. Installed via
	// SetConnectionContextTracker rather than taken by the constructor, which
	// already takes more arguments than is comfortable. Nil outside the pcap
	// chain, and nil-safe on every method it is used through.
	connectionContext      *ConnectionContextTracker
	connectionContextMutex sync.Mutex

	// Mutex protecting learnSessionID
	learnSessionMutex sync.Mutex

	// Whether to keep witness payloads intact. If false, witness payloads will be
	// obfuscated before being sent to the back end.
	sendWitnessPayloads bool

	// Always capture request and response payloads for the given paths.
	alwaysCapturePayloadsPathsRegex []*regexp.Regexp

	plugins []plugin.AkitaPlugin

	redactor *data_masks.Redactor

	telemetry telemetry.Tracker

	// Capture-diagnostics counters for the apidump session this collector
	// belongs to. One BackendCollector is created per apidump.Run() call (two
	// if HTTPS capture is also enabled), so stats being a field here -- rather
	// than a package-level counter -- is what keeps pairing outcomes and
	// negative-latency counts scoped to the pod this collector is uploading
	// witnesses for, instead of every pod the node happens to monitor.
	stats *capturestats.Stats
}

var _ LearnSessionCollector = (*BackendCollector)(nil)

func NewBackendCollector(
	svc akid.ServiceID,
	traceTags map[tags.Key]string,
	lrn akid.LearnSessionID,
	lc rest.LearnClient,
	redactor *data_masks.Redactor,
	maxWitnessSize_bytes optionals.Optional[int],
	packetCounts PacketCountConsumer,
	sendWitnessPayloads bool,
	alwaysCapturePayloads optionals.Optional[[]string],
	plugins []plugin.AkitaPlugin,
	uploadReportBuffers int,
	telemetry telemetry.Tracker,
	stats *capturestats.Stats,
) Collector {
	// Compile the regexps for the always capture payloads.
	alwaysCapturePayloadsPathsRegex := []*regexp.Regexp{}
	if paths, exists := alwaysCapturePayloads.Get(); exists {
		for _, path := range paths {
			reg, err := regexp.Compile(path)
			if err != nil {
				printer.Errorf("Invalid regex %s: %v", path, err)
				continue
			}
			alwaysCapturePayloadsPathsRegex = append(alwaysCapturePayloadsPathsRegex, reg)
		}
	}

	col := &BackendCollector{
		serviceID:                       svc,
		traceTags:                       traceTags,
		learnSessionID:                  lrn,
		learnClient:                     lc,
		flushDone:                       make(chan struct{}),
		plugins:                         plugins,
		sendWitnessPayloads:             sendWitnessPayloads,
		alwaysCapturePayloadsPathsRegex: alwaysCapturePayloadsPathsRegex,
		redactor:                        redactor,
		telemetry:                       telemetry,
		stats:                           stats,
	}

	col.reportBuffer = newReportBuffer(col, packetCounts, uploadBatchMaxSize_bytes, maxWitnessSize_bytes, sendWitnessPayloads, uploadReportBuffers)
	col.uploadReportBatch = batcher.NewInMemory(
		col.reportBuffer,
		uploadBatchFlushDuration,
	)

	go col.periodicFlush()

	return col
}

func (c *BackendCollector) Process(t akinet.ParsedNetworkTraffic) error {
	var isRequest bool
	var partial *learn.PartialWitness
	var parseHTTPErr error
	// akinet.ParsedNetworkTraffic carries no stream identity of its own; it
	// lives inside the content union, so this switch is the only place it can
	// be read.
	var streamID uuid.UUID
	switch content := t.Content.(type) {
	case akinet.HTTPRequest:
		isRequest = true
		streamID = content.StreamID
		partial, parseHTTPErr = learn.ParseHTTP(content)
	case akinet.HTTPResponse:
		streamID = content.StreamID
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
		// This message already passed prefilter, filters, rate limiting, and
		// sampling -- postfilter's PacketCountCollector counted it as a
		// request or response before we ever got here -- so this failure is
		// invisible to the prefilter/postfilter comparison. It is the other
		// half of the request or response we are about to silently drop:
		// whichever side of the pair this was, no witness will be produced
		// for it.
		c.stats.IncrWitnessParseFailed()
		c.telemetry.RateLimitError("parse HTTP", parseHTTPErr)
		c.reportTelemetryEvent("http_parse_failed_" + messageDirection(isRequest) + "_" + classifyParseHTTPError(parseHTTPErr))
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
			pair.computeProcessingLatency(c.stats, isRequest, t)

			// Backfill direction if the first-seen half didn't carry one. Both
			// halves of an eBPF pair report the same direction, so this is a
			// no-op there; it helps mixed producers.
			if pair.direction == akinet.DirectionUnknown {
				pair.direction = t.Direction
			}

			// If partial is the request, flip the src/dst in the pair before
			// reporting.
			if isRequest {
				pair.srcIP, pair.dstIP = pair.dstIP, pair.srcIP
				pair.srcPort, pair.dstPort = pair.dstPort, pair.srcPort
			}

			c.stats.IncrWitnessesPaired()
			c.queueUpload(pair)
			printer.Debugf("Completed witness %v direction=%s at %v -- %v\n",
				partial.PairKey, pair.direction, t.ObservationTime, t.FinalPacketTime)
		}()
	} else {
		// Store the partial witness for now, waiting for its pair or a
		// flush timeout.
		w := &witnessWithInfo{
			netInterface:           t.Interface,
			srcIP:                  t.SrcIP,
			srcPort:                uint16(t.SrcPort),
			dstIP:                  t.DstIP,
			dstPort:                uint16(t.DstPort),
			witness:                partial.Witness,
			observationTime:        t.ObservationTime,
			finalPacketTime:        t.FinalPacketTime,
			id:                     partial.PairKey,
			isRequest:              isRequest,
			streamID:               streamID,
			direction:              t.Direction,
			telemetryEventReporter: c.reportTelemetryEvent,
		}
		c.pairCache.Store(partial.PairKey, w)
		printer.Debugf("Partial witness %v request=%v at %v -- %v\n",
			partial.PairKey, isRequest, t.ObservationTime, t.FinalPacketTime)

	}
	return nil
}

func (w *witnessWithInfo) reportTelemetryEvent(event string) {
	if w.telemetryEventReporter != nil {
		w.telemetryEventReporter(event)
	}
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

var (
	cloudAPIEnvironmentsPathRE = regexp.MustCompile(`^/environments/[^/]+$`)
	cloudAPIHostnames          = sets.NewSet[string]()
)

func init() {
	cloudAPIHostnames.Insert("api.getpostman-stage.com")
	cloudAPIHostnames.Insert("api.getpostman.com")
	cloudAPIHostnames.Insert("api.postman.com")
	cloudAPIHostnamesEnv := os.Getenv("XXX_INSIGHTS_AGENT_CLOUD_API_HOSTNAMES")
	for _, hostname := range strings.Split(cloudAPIHostnamesEnv, " ") {
		cloudAPIHostnames.Insert(strings.ToLower(hostname))
	}
}

// Outbound-direction traffic is suppressed by dropOutboundCollector, which
// every chain feeding this collector installs ahead of rate limiting and the
// pair cache (see apidump.Run). It used to be dropped here instead, at upload
// time, which meant an outbound witness consumed witness budget, occupied a
// pair-cache slot, paired, incremented witness_paired and was redacted before
// being thrown away -- so witness_paired overcounted uploads by the outbound
// volume. Reinstating an upload-time gate would reintroduce that gap; the
// place to change this policy is dropOutboundCollector.

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
			w.reportTelemetryEvent("witness_dropped_plugin_error")
			return
		}
	}

	if !c.sendWitnessPayloads ||
		!shouldCapturePayload(w.witness, c.alwaysCapturePayloadsPathsRegex) {
		// Obfuscate the original value so type inference engine can use it on the
		// backend without revealing the actual value.
		c.redactor.ZeroAllPrimitives(w.witness.GetMethod())
	} else {
		c.redactor.RedactSensitiveData(w.witness.GetMethod())
	}

	c.uploadReportBatch.Add(rawReport{
		Witness: w,
	})
}

// SetUploadReporter installs an observer for upload outcomes. Passing nil
// disables reporting.
func (c *BackendCollector) SetUploadReporter(r UploadReporter) {
	c.uploadReporterMutex.Lock()
	defer c.uploadReporterMutex.Unlock()
	c.uploadReporter = r
}

// reportUpload records the outcome of one upload batch, if an observer is set.
func (c *BackendCollector) reportUpload(at time.Time, status UploadStatus) {
	c.uploadReporterMutex.Lock()
	reporter := c.uploadReporter
	c.uploadReporterMutex.Unlock()

	if reporter != nil {
		reporter.RecordUpload(at, status)
	}
}

func (c *BackendCollector) Close() error {
	defer c.redactor.StopPeriodicUpdates()
	close(c.flushDone)
	c.flushPairCache(time.Now())
	c.uploadReportBatch.Close()
	c.reportBuffer.WaitForUploads()
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
	totalWitnesses := 0
	flushedWitnesses := 0

	// Accumulated across the whole sweep and reported once below. A single
	// flush can expire thousands of witnesses (6,381 in one observed run), and
	// each telemetry call takes a lock shared by every target on the node.
	var expiredMissingResponse, expiredMissingRequest uint64

	// Stream keys of the witnesses expired by this sweep, plus which half each
	// was missing, collected here and classified after the Range returns.
	// Hashing is pure so it is safe under the witness lock; the tracker lookup
	// is not done here, which is what keeps witnessMutex and the tracker mutex
	// from ever being held at the same time.
	var expiredStreamKeys []uint64
	var expiredWasRequest []bool

	c.pairCache.Range(func(k, v interface{}) bool {
		e := v.(*witnessWithInfo)
		if e.observationTime.Before(cutoffTime) {
			// Lock the witness while it is being flushed
			// and unlock it after it is deleted from pairCache
			e.witnessMutex.Lock()
			defer e.witnessMutex.Unlock()

			// A zero key means no stream identity was retained, which
			// classifyPairExpiries reports as its own reason rather than
			// silently folding into "the companion never arrived".
			streamKey, _ := streamContextKey(e.streamID)
			expiredStreamKeys = append(expiredStreamKeys, streamKey)
			expiredWasRequest = append(expiredWasRequest, e.isRequest)

			// This witness never found its other half, and we are about to upload
			// it anyway. Record which half is missing: the back end will drop a
			// request-only witness as missing_status_code and a response-only one
			// as missing_latency, so these two counters are the agent-side
			// equivalents of those drop reasons.
			if e.isRequest {
				c.stats.IncrUnpairedRequestsFlushed()
				expiredMissingResponse++
			} else {
				c.stats.IncrUnpairedResponsesFlushed()
				expiredMissingRequest++
			}

			c.queueUpload(e)
			c.pairCache.Delete(k)

			flushedWitnesses += 1
		}
		totalWitnesses += 1
		return true
	})

	// Names match the half that is *missing*, not the half that expired: a
	// request-only witness expired without ever seeing its response.
	c.reportTelemetryCount("witness_pair_expired_response", expiredMissingResponse)
	c.reportTelemetryCount("witness_pair_expired_request", expiredMissingRequest)

	c.reportPairExpiryReasons(expiredStreamKeys, expiredWasRequest)

	if flushedWitnesses > 0 {
		printer.Debugf("Flushed %d unpaired witnesses, %d still waiting for a pair\n",
			flushedWitnesses, totalWitnesses-flushedWitnesses)
	}
}

// SetConnectionContextTracker installs the shared per-session tracker used to
// attribute pair-cache expiries. Must be synchronized: periodicFlush is
// started by the constructor, so the flush goroutine can be reading this
// field while Run is still wiring the collector up.
func (c *BackendCollector) SetConnectionContextTracker(tracker *ConnectionContextTracker) {
	c.connectionContextMutex.Lock()
	defer c.connectionContextMutex.Unlock()
	c.connectionContext = tracker
}

func (c *BackendCollector) getConnectionContextTracker() *ConnectionContextTracker {
	c.connectionContextMutex.Lock()
	defer c.connectionContextMutex.Unlock()
	return c.connectionContext
}

// pairExpiryReasonName maps a reason to the suffix used in both the telemetry
// event name and the diagnostics log line.
func pairExpiryReasonName(reason pairExpiryContext) string {
	switch reason {
	case pairExpiryContextPeerRejected:
		return "peer_rejected"
	case pairExpiryContextPeerNeverObserved:
		return "peer_never_observed"
	case pairExpiryContextPeerStreamUnknown:
		return "peer_stream_unknown"
	case pairExpiryContextPeerTrackerUnavailable:
		return "peer_tracker_unavailable"
	default:
		return "peer_unknown"
	}
}

// reportPairExpiryReasons partitions one sweep's expiries by why the missing
// half never arrived.
//
// Totals are accumulated across the whole sweep and reported once per
// (direction, reason), never once per witness: reportTelemetryCount's callback
// takes a node-wide lock shared by every target on the host, and a sweep can
// expire thousands of witnesses at once.
// TestFlushPairCacheBatchesExpiryTelemetry pins that contract.
func (c *BackendCollector) reportPairExpiryReasons(streamKeys []uint64, wasRequest []bool) {
	if len(streamKeys) == 0 {
		return
	}

	reasons := c.getConnectionContextTracker().classifyPairExpiries(streamKeys)

	// Indexed [wasRequest][reason]: a request-only witness (wasRequest) is the
	// one missing its response.
	missingResponse := map[pairExpiryContext]uint64{}
	missingRequest := map[pairExpiryContext]uint64{}

	for i, reason := range reasons {
		if wasRequest[i] {
			missingResponse[reason]++
		} else {
			missingRequest[reason]++
		}
	}

	for reason, count := range missingResponse {
		c.recordPairExpiryReason(true, reason, count)
	}
	for reason, count := range missingRequest {
		c.recordPairExpiryReason(false, reason, count)
	}
}

// recordPairExpiryReason reports one (direction, reason) bucket to both the
// session's diagnostics counters and the interval telemetry stream.
// missingResponse distinguishes a request-only witness from a response-only
// one, matching the naming of the witness_pair_expired_* totals these
// partition.
func (c *BackendCollector) recordPairExpiryReason(missingResponse bool, reason pairExpiryContext, count uint64) {
	if missingResponse {
		switch reason {
		case pairExpiryContextPeerRejected:
			c.stats.AddPairExpiredResponsePeerRejected(count)
		case pairExpiryContextPeerNeverObserved:
			c.stats.AddPairExpiredResponsePeerNeverObserved(count)
		case pairExpiryContextPeerStreamUnknown:
			c.stats.AddPairExpiredResponsePeerStreamUnknown(count)
		default:
			c.stats.AddPairExpiredResponsePeerTrackerUnavailable(count)
		}
	} else {
		switch reason {
		case pairExpiryContextPeerRejected:
			c.stats.AddPairExpiredRequestPeerRejected(count)
		case pairExpiryContextPeerNeverObserved:
			c.stats.AddPairExpiredRequestPeerNeverObserved(count)
		case pairExpiryContextPeerStreamUnknown:
			c.stats.AddPairExpiredRequestPeerStreamUnknown(count)
		default:
			c.stats.AddPairExpiredRequestPeerTrackerUnavailable(count)
		}
	}

	missing := "request"
	if missingResponse {
		missing = "response"
	}
	c.reportTelemetryCount("witness_pair_expired_"+missing+"_"+pairExpiryReasonName(reason), count)
}

func (c *BackendCollector) SetTelemetryEventReporter(reporter func(string)) {
	c.telemetryReporterMutex.Lock()
	defer c.telemetryReporterMutex.Unlock()
	c.telemetryReporter = reporter
}

func (c *BackendCollector) reportTelemetryEvent(event string) {
	c.telemetryReporterMutex.Lock()
	reporter := c.telemetryReporter
	c.telemetryReporterMutex.Unlock()
	if reporter != nil {
		reporter(event)
	}
}

// SetTelemetryCountReporter installs the target-scoped interval counter callback,
// for outcomes that occur in batches. Emitting one event per item would take the
// DaemonSet's node-wide telemetry lock once per item, which is worst during the
// high-loss periods these counters exist to describe.
func (c *BackendCollector) SetTelemetryCountReporter(reporter func(string, uint64)) {
	c.telemetryReporterMutex.Lock()
	defer c.telemetryReporterMutex.Unlock()
	c.telemetryCountReporter = reporter
}

func (c *BackendCollector) reportTelemetryCount(event string, count uint64) {
	if count == 0 {
		return
	}
	c.telemetryReporterMutex.Lock()
	reporter := c.telemetryCountReporter
	c.telemetryReporterMutex.Unlock()
	if reporter != nil {
		reporter(event, count)
	}
}

func messageDirection(isRequest bool) string {
	if isRequest {
		return "request"
	}
	return "response"
}

// classifyParseHTTPError returns a closed set and never exposes the error text.
func classifyParseHTTPError(err error) string {
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return "truncated"
	}
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &syntaxErr) || errors.As(err, &typeErr) {
		return "malformed"
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unsupported compression") || strings.Contains(message, "unsupported charset") || strings.Contains(message, "unrecognized compression") {
		return "unsupported_encoding"
	}
	return "other"
}
