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

func (s *Stats) IncrResponsesDroppedNoMatchingRequest() {
	if s == nil {
		return
	}
	atomic.AddUint64(&s.ResponsesDroppedNoMatchingRequest, 1)
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

// Snapshot is a plain-value copy of Stats for safe, consistent reading (avoids
// reading fields one at a time while they are still being incremented).
type Snapshot struct {
	PcapPacketsReceived, PcapPacketsDropped, PcapPacketsIfDropped uint64

	NilAssemblerContext, BadAssemblerContextType, NilAssemblerContextAfterParse,
	ZeroValuePacketTimestamp, LastPacketBeforeFirstPacket, ReassemblyGapFlushed uint64

	DiscardedRequests, DiscardedResponses, DiscardedOther uint64

	ResponsesDroppedNoMatchingRequest uint64

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

		ResponsesDroppedNoMatchingRequest: atomic.LoadUint64(&s.ResponsesDroppedNoMatchingRequest),

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
