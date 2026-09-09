// Package capturestats holds the capture-diagnostics counters for a single
// apidump session.
//
// These started out as package-level counters in pcap and trace. That is
// wrong for this agent: the Kubernetes DaemonSet runs one apidump.Run() call
// per monitored pod, all as goroutines inside a single OS process (see
// cmd/internal/kube/daemonset/apidump_process.go, StartApiDumpProcess). A
// package-level `var Count... uint64` is shared by every one of those
// goroutines, so a counter printed alongside one pod's client_id would
// actually be the sum across every pod that node happens to monitor --
// discovered by comparing a "Capture diagnostics" log line's pair[ok=...]
// against that same line's prefilter[req=...] for one client_id and finding
// the former many times larger than the latter could possibly be for one
// pod's own traffic.
//
// Stats fixes that by being an ordinary value, created once per apidump.Run()
// call and threaded through the pieces that increment it, the same way
// trace.PacketCounter (prefilter/postfilter) already was. One Stats instance
// per session means its numbers describe exactly the pod that session is
// capturing.
package capturestats

import "sync/atomic"

// Stats holds every capture-diagnostics counter for one apidump session.
// Fields are incremented with sync/atomic from whichever goroutine observes
// the event (packet capture, TCP reassembly, rate limiting, and witness
// pairing all run concurrently within one session), and read the same way
// when a diagnostics line is logged.
type Stats struct {
	// Reported by libpcap itself, polled from the capture handle. A drop here
	// happens before any parsing, so it costs us data we never had a chance to
	// see -- and it costs a multi-packet response far more often than a
	// single-packet request.
	PcapPacketsReceived  uint64
	PcapPacketsDropped   uint64
	PcapPacketsIfDropped uint64

	// TCP reassembly failures. NilAssemblerContext and BadAssemblerContextType
	// fire when a message's first byte carries no TCP sequence number, so the
	// parser is never created and the message is discarded outright.
	// ReassemblyGapFlushed counts TCP streams force-flushed because an
	// expected-but-missing segment sat unfilled past the reassembler's
	// timeout -- usually the downstream consequence of a kernel packet drop.
	NilAssemblerContext           uint64
	BadAssemblerContextType       uint64
	NilAssemblerContextAfterParse uint64
	ZeroValuePacketTimestamp      uint64
	LastPacketBeforeFirstPacket   uint64
	ReassemblyGapFlushed          uint64

	// The same NilAssemblerContext/BadAssemblerContextType failures, split by
	// which half of the exchange was discarded. A discarded response leaves a
	// witness with no response half; a discarded request produces no witness
	// at all, and its eventual response is later dropped by the rate limiter
	// with nothing to match against -- see ResponsesDroppedNoMatchingRequest.
	DiscardedRequests  uint64
	DiscardedResponses uint64
	DiscardedOther     uint64

	// A response we parsed successfully and then discarded because its
	// pairing key -- derived from TCP ack/seq numbers -- did not match any
	// request we were still tracking. The request, if any, has already gone
	// out as an unpaired witness by the time this fires.
	ResponsesDroppedNoMatchingRequest uint64

	// Traffic-proportional collector-chain drops. These are counters rather
	// than per-message telemetry events because they can each be the dominant
	// traffic class -- a broad host/path filter, a sample rate below 1.0, or an
	// outbound-heavy service can drop nearly every message -- and emitting one
	// event per drop would take the DaemonSet's node-wide telemetry lock once
	// per message on the capture path. See the note on
	// trace.BackendCollector.SetTelemetryCountReporter.
	RequestsFiltered         uint64
	ResponsesFiltered        uint64
	RequestsSampledOut       uint64
	ResponsesSampledOut      uint64
	RequestsDroppedOutbound  uint64
	ResponsesDroppedOutbound uint64

	// First-discard and unmatched-response reason counters recorded in the
	// rate-limit and user-traffic collector layers.
	RequestsRateLimited uint64
	RequestKeysExpired  uint64

	// Rejected-request tombstones the rate limiter declined to record because
	// its bounded map was full (see trace.rateLimitTombstoneMaxEntries). A
	// nonzero value means ResponsesDroppedNoMatchingRequestRateLimited
	// undercounts by this much, with those responses attributed to a weaker
	// reason instead -- it qualifies that partition the same way
	// ConnectionContextCapacityEvicted qualifies ResponseFirst.
	RateLimitTombstonesDropped                                 uint64
	RequestsDroppedAgentTraffic                                uint64
	ResponsesDroppedAgentTraffic                               uint64
	RequestsDroppedNginxTraffic                                uint64
	ResponsesDroppedNginxTraffic                               uint64
	ResponsesDroppedNoMatchingRequestRateLimited               uint64
	ResponsesDroppedNoMatchingRequestExpired                   uint64
	ResponsesDroppedNoMatchingRequestActiveRequestStream       uint64
	ResponsesDroppedNoMatchingRequestRequestSeenSameStream     uint64
	ResponsesDroppedNoMatchingRequestResponseFirst             uint64
	ResponsesDroppedNoMatchingRequestRequestSeenLocalCollector uint64
	ResponsesDroppedNoMatchingRequestRequestSeenOtherCollector uint64
	ResponsesDroppedNoMatchingRequestContextKeyInvalid         uint64
	ResponsesDroppedNoMatchingRequestContextUnavailable        uint64
	ResponsesDroppedNoMatchingRequestUnknown                   uint64

	// Health of the connection-context tracker that produces the
	// ResponseFirst/RequestSeen*Collector reasons above. Without these, a
	// ResponseFirst cannot be distinguished from a request the tracker did
	// observe and then forgot: ConnectionContextPruned counts entries dropped
	// for age, ConnectionContextCapacityEvicted counts entries dropped
	// arbitrarily at the tracker's entry cap, and either one turns a
	// would-be RequestSeenLocalCollector into a ResponseFirst.
	ConnectionContextPruned          uint64
	ConnectionContextCapacityEvicted uint64

	// Occupancy of the same tracker. Entries is a gauge (last observed size);
	// EntriesPeak is monotonic, so it can be shipped as an interval delta and
	// still sum to the session's peak -- see AddConnectionContextOccupancy.
	ConnectionContextEntries     uint64
	ConnectionContextEntriesPeak uint64

	// Attrition of the stream-keyed index that answers "was this witness's
	// companion message rejected before pairing". Counted separately from
	// ConnectionContextPruned above because the two describe different
	// populations -- connections there, TCP streams here -- and a single name
	// covering both would make neither readable. A stream lost from this index
	// turns a would-be PairExpired*PeerRejected into a PeerNeverObserved.
	UnmatchedResponseStreamPruned          uint64
	UnmatchedResponseStreamCapacityEvicted uint64

	// Why the missing half of an expired witness never arrived, partitioned
	// per direction. The names follow the existing witness_pair_expired_*
	// convention: "Response" means the witness was request-only and its
	// *response* never came.
	//
	// PeerRejected means a message on the same TCP stream reached the
	// rate-limit collector and was discarded as unmatched -- the companion
	// claim to ResponsesDroppedNoMatchingRequestRequestSeenSameStream. This is
	// stream-level, not message-level: a keep-alive stream carries many
	// exchanges, so it does not prove that *this* witness's companion was the
	// rejected one.
	//
	// Each direction's four counters sum to UnpairedRequestsFlushed and
	// UnpairedResponsesFlushed respectively.
	PairExpiredResponsePeerRejected           uint64
	PairExpiredResponsePeerNeverObserved      uint64
	PairExpiredResponsePeerStreamUnknown      uint64
	PairExpiredResponsePeerTrackerUnavailable uint64
	PairExpiredRequestPeerRejected            uint64
	PairExpiredRequestPeerNeverObserved       uint64
	PairExpiredRequestPeerStreamUnknown       uint64
	PairExpiredRequestPeerTrackerUnavailable  uint64

	// How witnesses left the pair cache: both halves present, request only
	// (missing_status_code at the back end), response only (missing_latency),
	// or two messages of the same direction merged into one malformed witness
	// because they collided on the same pairing key.
	WitnessesPaired          uint64
	UnpairedRequestsFlushed  uint64
	UnpairedResponsesFlushed uint64
	SameDirectionMerges      uint64

	// A response and request paired, but produced a negative processing
	// latency, bucketed by magnitude: sub-millisecond is timestamp noise,
	// sub-second is plausibly a server answering before the request body
	// finished uploading, and anything over a second is almost certainly a
	// mispairing (see SameDirectionMerges).
	NegativeLatencyUnder1ms uint64
	NegativeLatencyUnder1s  uint64
	NegativeLatencyOver1s   uint64

	// A request or response reached the backend collector -- so it already
	// passed prefilter, filters, rate limiting, and sampling -- but
	// learn.ParseHTTP then failed on it, so it was silently dropped with no
	// witness produced. This sits strictly after postfilter, so a shortfall
	// here does not show up as a postfilter-vs-prefilter gap; it can only be
	// seen here.
	WitnessParseFailed uint64
}

// New returns a zeroed Stats for one apidump session.
func New() *Stats {
	return &Stats{}
}

// Add* helpers keep call sites free of repeated &s.Field, atomic.AddUint64
// boilerplate and make each increment site read as "what happened", not "how
// it's counted".

// Every method below is a no-op on a nil receiver. A capture session should
// always have a real Stats -- see apidump.Run() -- but nil-safety here means
// a missing one (an uninitialized test fixture, a code path that forgot to
// thread it through) fails silently instead of panicking the capture
// pipeline.

func (s *Stats) AddPcapPacketsReceived(n uint64) {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.PcapPacketsReceived, n)
}
func (s *Stats) AddPcapPacketsDropped(n uint64) {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.PcapPacketsDropped, n)
}
func (s *Stats) AddPcapPacketsIfDropped(n uint64) {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.PcapPacketsIfDropped, n)
}

func (s *Stats) IncrNilAssemblerContext() {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.NilAssemblerContext, 1)
}
func (s *Stats) IncrBadAssemblerContextType() {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.BadAssemblerContextType, 1)
}
func (s *Stats) IncrNilAssemblerContextAfterParse() {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.NilAssemblerContextAfterParse, 1)
}
func (s *Stats) IncrZeroValuePacketTimestamp() {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.ZeroValuePacketTimestamp, 1)
}
func (s *Stats) IncrLastPacketBeforeFirstPacket() {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.LastPacketBeforeFirstPacket, 1)
}
func (s *Stats) AddReassemblyGapFlushed(n uint64) {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.ReassemblyGapFlushed, n)
}

func (s *Stats) IncrDiscardedRequests() {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.DiscardedRequests, 1)
}
func (s *Stats) IncrDiscardedResponses() {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.DiscardedResponses, 1)
}
func (s *Stats) IncrDiscardedOther() {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.DiscardedOther, 1)
}

func (s *Stats) IncrRequestsFiltered() {
	if s != nil {
		atomic.AddUint64(&s.RequestsFiltered, 1)
	}
}

func (s *Stats) IncrResponsesFiltered() {
	if s != nil {
		atomic.AddUint64(&s.ResponsesFiltered, 1)
	}
}

func (s *Stats) IncrRequestsSampledOut() {
	if s != nil {
		atomic.AddUint64(&s.RequestsSampledOut, 1)
	}
}

func (s *Stats) IncrResponsesSampledOut() {
	if s != nil {
		atomic.AddUint64(&s.ResponsesSampledOut, 1)
	}
}

func (s *Stats) IncrRequestsDroppedOutbound() {
	if s != nil {
		atomic.AddUint64(&s.RequestsDroppedOutbound, 1)
	}
}

func (s *Stats) IncrResponsesDroppedOutbound() {
	if s != nil {
		atomic.AddUint64(&s.ResponsesDroppedOutbound, 1)
	}
}

func (s *Stats) IncrResponsesDroppedNoMatchingRequest() {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.ResponsesDroppedNoMatchingRequest, 1)
}

func (s *Stats) IncrRequestsRateLimited() {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.RequestsRateLimited, 1)
}

func (s *Stats) IncrRateLimitTombstonesDropped() {
	if s != nil {
		atomic.AddUint64(&s.RateLimitTombstonesDropped, 1)
	}
}

func (s *Stats) AddRequestKeysExpired(n uint64) {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.RequestKeysExpired, n)
}

func (s *Stats) IncrRequestsDroppedAgentTraffic() {
	if s != nil {
		atomic.AddUint64(&s.RequestsDroppedAgentTraffic, 1)
	}
}

func (s *Stats) IncrResponsesDroppedAgentTraffic() {
	if s != nil {
		atomic.AddUint64(&s.ResponsesDroppedAgentTraffic, 1)
	}
}

func (s *Stats) IncrRequestsDroppedNginxTraffic() {
	if s != nil {
		atomic.AddUint64(&s.RequestsDroppedNginxTraffic, 1)
	}
}

func (s *Stats) IncrResponsesDroppedNginxTraffic() {
	if s != nil {
		atomic.AddUint64(&s.ResponsesDroppedNginxTraffic, 1)
	}
}

func (s *Stats) IncrResponsesDroppedNoMatchingRequestRateLimited() {
	if s != nil {
		atomic.AddUint64(&s.ResponsesDroppedNoMatchingRequestRateLimited, 1)
	}
}

func (s *Stats) IncrResponsesDroppedNoMatchingRequestExpired() {
	if s != nil {
		atomic.AddUint64(&s.ResponsesDroppedNoMatchingRequestExpired, 1)
	}
}

func (s *Stats) IncrResponsesDroppedNoMatchingRequestActiveRequestStream() {
	if s != nil {
		atomic.AddUint64(&s.ResponsesDroppedNoMatchingRequestActiveRequestStream, 1)
	}
}

func (s *Stats) IncrResponsesDroppedNoMatchingRequestRequestSeenSameStream() {
	if s != nil {
		atomic.AddUint64(&s.ResponsesDroppedNoMatchingRequestRequestSeenSameStream, 1)
	}
}

func (s *Stats) IncrResponsesDroppedNoMatchingRequestResponseFirst() {
	if s != nil {
		atomic.AddUint64(&s.ResponsesDroppedNoMatchingRequestResponseFirst, 1)
	}
}

func (s *Stats) IncrResponsesDroppedNoMatchingRequestRequestSeenLocalCollector() {
	if s != nil {
		atomic.AddUint64(&s.ResponsesDroppedNoMatchingRequestRequestSeenLocalCollector, 1)
	}
}

func (s *Stats) IncrResponsesDroppedNoMatchingRequestRequestSeenOtherCollector() {
	if s != nil {
		atomic.AddUint64(&s.ResponsesDroppedNoMatchingRequestRequestSeenOtherCollector, 1)
	}
}

func (s *Stats) IncrResponsesDroppedNoMatchingRequestContextKeyInvalid() {
	if s != nil {
		atomic.AddUint64(&s.ResponsesDroppedNoMatchingRequestContextKeyInvalid, 1)
	}
}

func (s *Stats) IncrResponsesDroppedNoMatchingRequestContextUnavailable() {
	if s != nil {
		atomic.AddUint64(&s.ResponsesDroppedNoMatchingRequestContextUnavailable, 1)
	}
}

func (s *Stats) IncrResponsesDroppedNoMatchingRequestUnknown() {
	if s != nil {
		atomic.AddUint64(&s.ResponsesDroppedNoMatchingRequestUnknown, 1)
	}
}

func (s *Stats) AddConnectionContextPruned(n uint64) {
	if s != nil {
		atomic.AddUint64(&s.ConnectionContextPruned, n)
	}
}

func (s *Stats) AddConnectionContextCapacityEvicted(n uint64) {
	if s != nil {
		atomic.AddUint64(&s.ConnectionContextCapacityEvicted, n)
	}
}

// AddConnectionContextOccupancy records the tracker's current entry count.
//
// Entries is overwritten rather than accumulated: it is a gauge, and summing
// successive observations of a map's size would be meaningless.
//
// EntriesPeak is a running maximum, which is what makes the occupancy
// reportable at all. The telemetry path ships interval deltas of monotonic
// counters and the back end sums them per window (see
// apidump.reportSourceFunnel), so a gauge cannot be expressed there. Deltas
// of a running maximum can: they sum to the peak over whatever range is
// queried, and a window that saw no new high reports nothing.
//
// The caller is expected to hold whatever lock guards the map it measured;
// the atomics here exist for concurrent Snapshot readers, not for
// serializing two writers racing on the peak.
func (s *Stats) AddConnectionContextOccupancy(entries uint64) {
	if s == nil {
		return
	}
	atomic.StoreUint64(&s.ConnectionContextEntries, entries)
	if entries > atomic.LoadUint64(&s.ConnectionContextEntriesPeak) {
		atomic.StoreUint64(&s.ConnectionContextEntriesPeak, entries)
	}
}

func (s *Stats) AddUnmatchedResponseStreamPruned(n uint64) {
	if s != nil {
		atomic.AddUint64(&s.UnmatchedResponseStreamPruned, n)
	}
}

func (s *Stats) AddUnmatchedResponseStreamCapacityEvicted(n uint64) {
	if s != nil {
		atomic.AddUint64(&s.UnmatchedResponseStreamCapacityEvicted, n)
	}
}

// Add* rather than Incr* for the pair-expiry reasons below: one pair-cache
// sweep can expire thousands of witnesses at once, so the caller accumulates
// per-sweep totals and adds them in a single call per bucket.

func (s *Stats) AddPairExpiredResponsePeerRejected(n uint64) {
	if s != nil {
		atomic.AddUint64(&s.PairExpiredResponsePeerRejected, n)
	}
}

func (s *Stats) AddPairExpiredResponsePeerNeverObserved(n uint64) {
	if s != nil {
		atomic.AddUint64(&s.PairExpiredResponsePeerNeverObserved, n)
	}
}

func (s *Stats) AddPairExpiredResponsePeerStreamUnknown(n uint64) {
	if s != nil {
		atomic.AddUint64(&s.PairExpiredResponsePeerStreamUnknown, n)
	}
}

func (s *Stats) AddPairExpiredResponsePeerTrackerUnavailable(n uint64) {
	if s != nil {
		atomic.AddUint64(&s.PairExpiredResponsePeerTrackerUnavailable, n)
	}
}

func (s *Stats) AddPairExpiredRequestPeerRejected(n uint64) {
	if s != nil {
		atomic.AddUint64(&s.PairExpiredRequestPeerRejected, n)
	}
}

func (s *Stats) AddPairExpiredRequestPeerNeverObserved(n uint64) {
	if s != nil {
		atomic.AddUint64(&s.PairExpiredRequestPeerNeverObserved, n)
	}
}

func (s *Stats) AddPairExpiredRequestPeerStreamUnknown(n uint64) {
	if s != nil {
		atomic.AddUint64(&s.PairExpiredRequestPeerStreamUnknown, n)
	}
}

func (s *Stats) AddPairExpiredRequestPeerTrackerUnavailable(n uint64) {
	if s != nil {
		atomic.AddUint64(&s.PairExpiredRequestPeerTrackerUnavailable, n)
	}
}

func (s *Stats) IncrWitnessesPaired() {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.WitnessesPaired, 1)
}
func (s *Stats) IncrUnpairedRequestsFlushed() {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.UnpairedRequestsFlushed, 1)
}
func (s *Stats) IncrUnpairedResponsesFlushed() {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.UnpairedResponsesFlushed, 1)
}
func (s *Stats) IncrSameDirectionMerges() {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.SameDirectionMerges, 1)
}

func (s *Stats) IncrNegativeLatencyUnder1ms() {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.NegativeLatencyUnder1ms, 1)
}
func (s *Stats) IncrNegativeLatencyUnder1s() {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.NegativeLatencyUnder1s, 1)
}
func (s *Stats) IncrNegativeLatencyOver1s() {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.NegativeLatencyOver1s, 1)
}

func (s *Stats) IncrWitnessParseFailed() {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.WitnessParseFailed, 1)
}

// RecordNegativeLatency buckets a negative processing latency, in
// milliseconds, into the appropriate counter.
func (s *Stats) RecordNegativeLatency(latencyMs float32) {
	if s == nil {
		return
	}
	switch {
	case latencyMs > -1.0:
		s.IncrNegativeLatencyUnder1ms()
	case latencyMs > -1000.0:
		s.IncrNegativeLatencyUnder1s()
	default:
		s.IncrNegativeLatencyOver1s()
	}
}

// Snapshot is a plain-value copy of Stats for safe reading/formatting.
// It loads each counter atomically to avoid data races with concurrent increments.
type Snapshot struct {
	PcapPacketsReceived, PcapPacketsDropped, PcapPacketsIfDropped uint64

	NilAssemblerContext, BadAssemblerContextType, NilAssemblerContextAfterParse,
	ZeroValuePacketTimestamp, LastPacketBeforeFirstPacket, ReassemblyGapFlushed uint64

	DiscardedRequests, DiscardedResponses, DiscardedOther uint64

	RequestsFiltered, ResponsesFiltered               uint64
	RequestsSampledOut, ResponsesSampledOut           uint64
	RequestsDroppedOutbound, ResponsesDroppedOutbound uint64

	ResponsesDroppedNoMatchingRequest                                                              uint64
	RequestsRateLimited, RequestKeysExpired                                                        uint64
	RateLimitTombstonesDropped                                                                     uint64
	RequestsDroppedAgentTraffic, ResponsesDroppedAgentTraffic                                      uint64
	RequestsDroppedNginxTraffic, ResponsesDroppedNginxTraffic                                      uint64
	ResponsesDroppedNoMatchingRequestRateLimited, ResponsesDroppedNoMatchingRequestExpired         uint64
	ResponsesDroppedNoMatchingRequestActiveRequestStream, ResponsesDroppedNoMatchingRequestUnknown uint64
	ResponsesDroppedNoMatchingRequestRequestSeenSameStream                                         uint64
	ResponsesDroppedNoMatchingRequestResponseFirst                                                 uint64
	ResponsesDroppedNoMatchingRequestRequestSeenLocalCollector                                     uint64
	ResponsesDroppedNoMatchingRequestRequestSeenOtherCollector                                     uint64
	ResponsesDroppedNoMatchingRequestContextKeyInvalid                                             uint64
	ResponsesDroppedNoMatchingRequestContextUnavailable                                            uint64

	ConnectionContextPruned, ConnectionContextCapacityEvicted uint64
	ConnectionContextEntries, ConnectionContextEntriesPeak    uint64

	UnmatchedResponseStreamPruned, UnmatchedResponseStreamCapacityEvicted uint64

	PairExpiredResponsePeerRejected, PairExpiredResponsePeerNeverObserved           uint64
	PairExpiredResponsePeerStreamUnknown, PairExpiredResponsePeerTrackerUnavailable uint64
	PairExpiredRequestPeerRejected, PairExpiredRequestPeerNeverObserved             uint64
	PairExpiredRequestPeerStreamUnknown, PairExpiredRequestPeerTrackerUnavailable   uint64

	WitnessesPaired, UnpairedRequestsFlushed, UnpairedResponsesFlushed, SameDirectionMerges uint64

	NegativeLatencyUnder1ms, NegativeLatencyUnder1s, NegativeLatencyOver1s uint64

	WitnessParseFailed uint64
}

// Snapshot reads every counter with atomic.LoadUint64 and returns the result
// as plain values, safe to format without further synchronization.
func (s *Stats) Snapshot() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	return Snapshot{
		PcapPacketsReceived:  atomic.LoadUint64(&s.PcapPacketsReceived),
		PcapPacketsDropped:   atomic.LoadUint64(&s.PcapPacketsDropped),
		PcapPacketsIfDropped: atomic.LoadUint64(&s.PcapPacketsIfDropped),

		NilAssemblerContext:           atomic.LoadUint64(&s.NilAssemblerContext),
		BadAssemblerContextType:       atomic.LoadUint64(&s.BadAssemblerContextType),
		NilAssemblerContextAfterParse: atomic.LoadUint64(&s.NilAssemblerContextAfterParse),
		ZeroValuePacketTimestamp:      atomic.LoadUint64(&s.ZeroValuePacketTimestamp),
		LastPacketBeforeFirstPacket:   atomic.LoadUint64(&s.LastPacketBeforeFirstPacket),
		ReassemblyGapFlushed:          atomic.LoadUint64(&s.ReassemblyGapFlushed),

		DiscardedRequests:  atomic.LoadUint64(&s.DiscardedRequests),
		DiscardedResponses: atomic.LoadUint64(&s.DiscardedResponses),
		DiscardedOther:     atomic.LoadUint64(&s.DiscardedOther),

		RequestsFiltered:         atomic.LoadUint64(&s.RequestsFiltered),
		ResponsesFiltered:        atomic.LoadUint64(&s.ResponsesFiltered),
		RequestsSampledOut:       atomic.LoadUint64(&s.RequestsSampledOut),
		ResponsesSampledOut:      atomic.LoadUint64(&s.ResponsesSampledOut),
		RequestsDroppedOutbound:  atomic.LoadUint64(&s.RequestsDroppedOutbound),
		ResponsesDroppedOutbound: atomic.LoadUint64(&s.ResponsesDroppedOutbound),

		ResponsesDroppedNoMatchingRequest:                          atomic.LoadUint64(&s.ResponsesDroppedNoMatchingRequest),
		RequestsRateLimited:                                        atomic.LoadUint64(&s.RequestsRateLimited),
		RequestKeysExpired:                                         atomic.LoadUint64(&s.RequestKeysExpired),
		RateLimitTombstonesDropped:                                 atomic.LoadUint64(&s.RateLimitTombstonesDropped),
		RequestsDroppedAgentTraffic:                                atomic.LoadUint64(&s.RequestsDroppedAgentTraffic),
		ResponsesDroppedAgentTraffic:                               atomic.LoadUint64(&s.ResponsesDroppedAgentTraffic),
		RequestsDroppedNginxTraffic:                                atomic.LoadUint64(&s.RequestsDroppedNginxTraffic),
		ResponsesDroppedNginxTraffic:                               atomic.LoadUint64(&s.ResponsesDroppedNginxTraffic),
		ResponsesDroppedNoMatchingRequestRateLimited:               atomic.LoadUint64(&s.ResponsesDroppedNoMatchingRequestRateLimited),
		ResponsesDroppedNoMatchingRequestExpired:                   atomic.LoadUint64(&s.ResponsesDroppedNoMatchingRequestExpired),
		ResponsesDroppedNoMatchingRequestActiveRequestStream:       atomic.LoadUint64(&s.ResponsesDroppedNoMatchingRequestActiveRequestStream),
		ResponsesDroppedNoMatchingRequestRequestSeenSameStream:     atomic.LoadUint64(&s.ResponsesDroppedNoMatchingRequestRequestSeenSameStream),
		ResponsesDroppedNoMatchingRequestResponseFirst:             atomic.LoadUint64(&s.ResponsesDroppedNoMatchingRequestResponseFirst),
		ResponsesDroppedNoMatchingRequestRequestSeenLocalCollector: atomic.LoadUint64(&s.ResponsesDroppedNoMatchingRequestRequestSeenLocalCollector),
		ResponsesDroppedNoMatchingRequestRequestSeenOtherCollector: atomic.LoadUint64(&s.ResponsesDroppedNoMatchingRequestRequestSeenOtherCollector),
		ResponsesDroppedNoMatchingRequestContextKeyInvalid:         atomic.LoadUint64(&s.ResponsesDroppedNoMatchingRequestContextKeyInvalid),
		ResponsesDroppedNoMatchingRequestContextUnavailable:        atomic.LoadUint64(&s.ResponsesDroppedNoMatchingRequestContextUnavailable),
		ResponsesDroppedNoMatchingRequestUnknown:                   atomic.LoadUint64(&s.ResponsesDroppedNoMatchingRequestUnknown),

		ConnectionContextPruned:          atomic.LoadUint64(&s.ConnectionContextPruned),
		ConnectionContextCapacityEvicted: atomic.LoadUint64(&s.ConnectionContextCapacityEvicted),
		ConnectionContextEntries:         atomic.LoadUint64(&s.ConnectionContextEntries),
		ConnectionContextEntriesPeak:     atomic.LoadUint64(&s.ConnectionContextEntriesPeak),

		UnmatchedResponseStreamPruned:          atomic.LoadUint64(&s.UnmatchedResponseStreamPruned),
		UnmatchedResponseStreamCapacityEvicted: atomic.LoadUint64(&s.UnmatchedResponseStreamCapacityEvicted),

		PairExpiredResponsePeerRejected:           atomic.LoadUint64(&s.PairExpiredResponsePeerRejected),
		PairExpiredResponsePeerNeverObserved:      atomic.LoadUint64(&s.PairExpiredResponsePeerNeverObserved),
		PairExpiredResponsePeerStreamUnknown:      atomic.LoadUint64(&s.PairExpiredResponsePeerStreamUnknown),
		PairExpiredResponsePeerTrackerUnavailable: atomic.LoadUint64(&s.PairExpiredResponsePeerTrackerUnavailable),
		PairExpiredRequestPeerRejected:            atomic.LoadUint64(&s.PairExpiredRequestPeerRejected),
		PairExpiredRequestPeerNeverObserved:       atomic.LoadUint64(&s.PairExpiredRequestPeerNeverObserved),
		PairExpiredRequestPeerStreamUnknown:       atomic.LoadUint64(&s.PairExpiredRequestPeerStreamUnknown),
		PairExpiredRequestPeerTrackerUnavailable:  atomic.LoadUint64(&s.PairExpiredRequestPeerTrackerUnavailable),

		WitnessesPaired:          atomic.LoadUint64(&s.WitnessesPaired),
		UnpairedRequestsFlushed:  atomic.LoadUint64(&s.UnpairedRequestsFlushed),
		UnpairedResponsesFlushed: atomic.LoadUint64(&s.UnpairedResponsesFlushed),
		SameDirectionMerges:      atomic.LoadUint64(&s.SameDirectionMerges),

		NegativeLatencyUnder1ms: atomic.LoadUint64(&s.NegativeLatencyUnder1ms),
		NegativeLatencyUnder1s:  atomic.LoadUint64(&s.NegativeLatencyUnder1s),
		NegativeLatencyOver1s:   atomic.LoadUint64(&s.NegativeLatencyOver1s),

		WitnessParseFailed: atomic.LoadUint64(&s.WitnessParseFailed),
	}
}
