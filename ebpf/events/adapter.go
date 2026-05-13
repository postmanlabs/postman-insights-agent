// SPDX-License-Identifier: Apache-2.0

package events

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/memview"
	"github.com/google/uuid"
)

// MaxPendingPerFlow caps the bytes we will buffer for a single flow while
// waiting for the FactorySelector to commit to a parser. Without this cap,
// a malformed or pathological stream that never produces a parseable HTTP
// message could grow unbounded. The value mirrors OBI's `large_buffers`
// limit at the user-space side.
const MaxPendingPerFlow = 64 * 1024

// Adapter feeds decrypted-byte events from a Reader into the existing akinet
// HTTP/HTTP2 parsers, producing akinet.ParsedNetworkTraffic records that are
// indistinguishable (downstream) from the pcap path's output.
//
// Per-flow state machine:
//
//   For each FlowKey (PID, SSLCtx, Direction):
//     - Incoming bytes are appended to a per-flow pending buffer.
//     - With no current parser: consult the FactorySelector.
//         Accept       → create parser, hand pending bytes to Parse.
//         NeedMoreData → keep pending bytes, return.
//         Reject       → drop the flow permanently.
//     - With a current parser: call Parse(pending, false). On a non-nil
//       result, emit a ParsedNetworkTraffic on Out, clear the parser, and
//       re-enter the "no parser" branch with any unused tail bytes (this
//       handles HTTP keep-alive pipelining: one TCP/SSL flow carrying
//       N back-to-back requests or responses).
//
// The flow is forgotten after a configurable idle timeout (default 30s) or
// when an SSL_shutdown event arrives (Phase 2+).
//
// IP/port synthesis: Phase 1 (this code) leaves SrcIP/DstIP zero and stashes
// "ebpf-pid-<N>" in the Interface field for traceability. Phase 2 task 1's
// follow-up will read /proc/<pid>/net/tcp via the SSL*→fd map and synthesise
// the real 4-tuple. See docs/https-capture-design.md §5.4.
type Adapter struct {
	// FactorySelector picks the right parser for a new flow. Pass the same
	// selector the pcap path uses.
	FactorySelector akinet.TCPParserFactorySelector

	// Out receives one ParsedNetworkTraffic per parsed HTTP message.
	Out chan<- akinet.ParsedNetworkTraffic

	mu    sync.Mutex
	flows map[FlowKey]*flowState

	// Counters exported for telemetry / tests.
	MessagesEmitted uint64
	FlowsDropped    uint64
}

type flowState struct {
	parser    akinet.TCPParser
	pending   memview.MemView
	bidiID    akinet.TCPBidiID
	msgSeq    int
	firstSeen time.Time
	lastSeen  time.Time
	totalIn   int  // total bytes ever observed on this flow
	dropped   bool // permanent: malformed or oversized
	ifaceTag  string
}

// NewAdapter constructs an adapter wired to an output channel.
func NewAdapter(fs akinet.TCPParserFactorySelector, out chan<- akinet.ParsedNetworkTraffic) *Adapter {
	return &Adapter{
		FactorySelector: fs,
		Out:             out,
		flows:           make(map[FlowKey]*flowState),
	}
}

// Feed pushes one decrypted-bytes event into the adapter. Thread-safe.
//
// The event's payload slice is only valid for the duration of this call; we
// copy bytes into the per-flow pending buffer before returning.
func (a *Adapter) Feed(ev *SSLEvent, monoEpoch time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := ev.Key()
	st := a.flows[key]
	if st == nil {
		st = &flowState{
			firstSeen: ev.Time(monoEpoch),
			bidiID:    akinet.TCPBidiID(uuid.New()),
			ifaceTag:  fmt.Sprintf("ebpf-pid-%d", ev.PID),
		}
		a.flows[key] = st
	}
	if st.dropped {
		return
	}
	st.lastSeen = ev.Time(monoEpoch)
	st.totalIn += int(ev.LenCaptured)

	// Copy bytes — the underlying ringbuf record is reused once Feed returns.
	chunk := append([]byte(nil), ev.Bytes()...)
	st.pending.Append(memview.New(chunk))

	a.drain(key, st, ev.Time(monoEpoch))
}

// drain runs the parser state machine until no progress can be made.
// Caller holds a.mu.
func (a *Adapter) drain(key FlowKey, st *flowState, now time.Time) {
	for st.pending.Len() > 0 && !st.dropped {
		if st.parser == nil {
			factory, decision, discardFront := a.FactorySelector.Select(st.pending, false)
			if discardFront > 0 {
				st.pending = st.pending.SubView(discardFront, st.pending.Len())
			}
			switch decision {
			case akinet.Reject:
				a.dropFlow(key, st)
				return
			case akinet.NeedMoreData:
				if st.pending.Len() > MaxPendingPerFlow {
					a.dropFlow(key, st)
				}
				return
			case akinet.Accept:
				// initialSeq/initialAck are zero — we don't have TCP seq numbers
				// in the eBPF path, and the akihttp parser doesn't depend on
				// them for correctness, only for cross-pcap reassembly pairing
				// (which doesn't apply here: our bidiID is synthetic).
				st.parser = factory.CreateParser(st.bidiID, 0, 0)
			}
		}

		result, unused, _, err := st.parser.Parse(st.pending, false)
		if err != nil {
			// Parse error — flow is permanently un-parseable.
			a.dropFlow(key, st)
			return
		}
		if result == nil {
			// Parser absorbed all bytes and awaits more. Clear pending; next
			// event will append fresh bytes.
			st.pending.Clear()
			return
		}

		// Got a complete message. Emit it and continue with unused tail.
		a.Out <- a.toPNT(st, result, now)
		a.MessagesEmitted++
		st.msgSeq++
		st.parser = nil
		st.pending = unused
	}
}

// dropFlow marks a flow as permanently un-parseable and releases its buffer.
// Caller holds a.mu.
func (a *Adapter) dropFlow(key FlowKey, st *flowState) {
	st.dropped = true
	st.pending.Clear()
	st.parser = nil
	a.FlowsDropped++
	_ = key // retained for future Out emission of a "DroppedBytes" record
}

// toPNT wraps a parser result in the ParsedNetworkTraffic envelope that the
// downstream pipeline expects. Phase 1 leaves IPs zero; Phase 2 follow-up
// fills them from /proc/<pid>/net/tcp.
func (a *Adapter) toPNT(st *flowState, c akinet.ParsedNetworkContent, now time.Time) akinet.ParsedNetworkTraffic {
	return akinet.ParsedNetworkTraffic{
		SrcIP:           net.IPv4zero,
		DstIP:           net.IPv4zero,
		SrcPort:         0,
		DstPort:         0,
		Content:         c,
		Interface:       st.ifaceTag,
		ObservationTime: st.firstSeen,
		FinalPacketTime: now,
	}
}

// GC removes flows idle for longer than `maxIdle`. Call periodically.
func (a *Adapter) GC(now time.Time, maxIdle time.Duration) int {
	a.mu.Lock()
	defer a.mu.Unlock()

	dropped := 0
	for k, st := range a.flows {
		if now.Sub(st.lastSeen) > maxIdle {
			delete(a.flows, k)
			dropped++
		}
	}
	return dropped
}

// CloseFlow forgets state for one flow. Called when an SSL_shutdown event
// arrives or the parent process exits.
func (a *Adapter) CloseFlow(key FlowKey) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.flows, key)
}

// Snapshot returns counts for telemetry.
func (a *Adapter) Snapshot() (numFlows int, totalBytes int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	numFlows = len(a.flows)
	for _, st := range a.flows {
		totalBytes += st.totalIn
	}
	return
}
