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

	// Resolver, when non-nil, is consulted to fill SrcIP/DstIP/SrcPort/DstPort
	// on emitted ParsedNetworkTraffic from the (pid, fd) carried in each
	// SSLEvent. When nil, IPs are left zero (the Phase 1 spike behaviour).
	Resolver *Resolver

	mu    sync.Mutex
	flows map[FlowKey]*flowState

	// resolved caches socket tuples by (pid, ssl_ctx) so the ingress and
	// egress sides of the same TLS connection share one /proc lookup, and
	// so a successful early-event resolve survives even after the socket
	// has been closed.
	resolved map[resolvedKey]SocketInfo

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

	// Body-truncation accounting (Phase 4 / design §7.3 gap #2).
	//
	// When the BPF layer caps a single event (LenTotal > LenCaptured), we
	// note it here so the message currently being assembled in `pending`
	// can be tagged with synthetic headers when emitted. We track:
	//
	//   - pendingTruncated  = at least one event contributing to the
	//                         in-flight message was truncated.
	//   - pendingDroppedBytes = sum of (LenTotal - LenCaptured) across
	//                         those events. This is the closest we can
	//                         honestly state about the original size; the
	//                         full request body may also have a non-truncated
	//                         tail, so the synthetic header is documented as
	//                         "bytes dropped" rather than "original length"
	//                         to avoid misleading downstream consumers.
	//
	// Reset to zero whenever a complete message is emitted from `pending`.
	pendingTruncated    bool
	pendingDroppedBytes uint64

	// HTTP/2 path: if h2 != nil, all bytes for this flow are routed to
	// the stateful HTTP/2 decoder instead of the akinet single-use parser.
	// Detection happens on the first bytes via IsHTTP2Preface.
	h2 *h2State

	// Resolved (or cached) socket info for this flow. Resolved on first
	// event with a valid fd; reused for the lifetime of the flow.
	socketResolved bool
	localIP        net.IP
	localPort      int
	remoteIP       net.IP
	remotePort     int
	pid            uint32 // for Forget on flow close
}

// resolvedKey includes fd because nginx (and other servers) maintain SSL*
// connection pools — the same SSL* pointer is reused across distinct TCP
// connections, each with a different fd. Keying only by (pid, ssl_ctx) would
// return stale tuples from a previous connection.
type resolvedKey struct {
	PID    uint32
	SSLCtx uint64
	FD     int32
}

// NewAdapter constructs an adapter wired to an output channel.
func NewAdapter(fs akinet.TCPParserFactorySelector, out chan<- akinet.ParsedNetworkTraffic) *Adapter {
	return &Adapter{
		FactorySelector: fs,
		Out:             out,
		flows:           make(map[FlowKey]*flowState),
		resolved:        make(map[resolvedKey]SocketInfo),
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
			pid:       ev.PID,
		}
		a.flows[key] = st
	}
	if st.dropped {
		return
	}

	// Lazily resolve the 4-tuple from (pid, fd). On success we cache by
	// (pid, ssl_ctx, fd) — fd is needed because SSL* pointers are reused
	// across distinct TCP connections by servers with connection pools.
	// Same (pid, ssl_ctx, fd) means same actual connection and the tuple
	// is safe to share between ingress and egress and between events whose
	// fd has been reclaimed.
	if !st.socketResolved && a.Resolver != nil && ev.FD >= 0 {
		rk := resolvedKey{PID: ev.PID, SSLCtx: ev.SSLCtx, FD: ev.FD}
		if info, ok := a.resolved[rk]; ok {
			st.localIP = info.LocalIP
			st.localPort = info.LocalPort
			st.remoteIP = info.RemoteIP
			st.remotePort = info.RemotePort
			st.socketResolved = true
		} else if info, err := a.Resolver.Resolve(ev.PID, ev.FD); err == nil {
			a.resolved[rk] = info
			st.localIP = info.LocalIP
			st.localPort = info.LocalPort
			st.remoteIP = info.RemoteIP
			st.remotePort = info.RemotePort
			st.socketResolved = true
		}
		// Failed lookups are non-fatal; we'll retry on the next event.
	}
	st.lastSeen = ev.Time(monoEpoch)
	st.totalIn += int(ev.LenCaptured)

	// If we've already committed this flow to the HTTP/2 path, stay there.
	if st.h2 != nil {
		for _, pnt := range st.h2.feed(ev.Bytes(), ev.Time(monoEpoch), st.ifaceTag) {
			// Backfill source/dest IPs from the resolver cache, mirroring
			// the HTTP/1 toPNT path.
			if st.socketResolved {
				if key.Direction == DirEgress {
					pnt.SrcIP, pnt.SrcPort = st.localIP, st.localPort
					pnt.DstIP, pnt.DstPort = st.remoteIP, st.remotePort
				} else {
					pnt.SrcIP, pnt.SrcPort = st.remoteIP, st.remotePort
					pnt.DstIP, pnt.DstPort = st.localIP, st.localPort
				}
			}
			a.Out <- pnt
			a.MessagesEmitted++
		}
		return
	}

	// Detect HTTP/2 on the first bytes we see on this flow.
	// Two paths: full preface (when we attach before the connection opens)
	// or a recognisable frame header (when we attach mid-connection, which is
	// the common case for gotls because the TLS handshake + preface complete
	// before the uprobes catch their first non-handshake call).
	if st.pending.Len() == 0 && (IsHTTP2Preface(ev.Bytes()) || IsHTTP2Frame(ev.Bytes())) {
		st.h2 = newH2State(st.ifaceTag)
		for _, pnt := range st.h2.feed(ev.Bytes(), ev.Time(monoEpoch), st.ifaceTag) {
			if st.socketResolved {
				if key.Direction == DirEgress {
					pnt.SrcIP, pnt.SrcPort = st.localIP, st.localPort
					pnt.DstIP, pnt.DstPort = st.remoteIP, st.remotePort
				} else {
					pnt.SrcIP, pnt.SrcPort = st.remoteIP, st.remotePort
					pnt.DstIP, pnt.DstPort = st.localIP, st.localPort
				}
			}
			a.Out <- pnt
			a.MessagesEmitted++
		}
		return
	}

	// Body-truncation accounting (gap #2). If this event was truncated by
	// the BPF layer (LenTotal > LenCaptured), remember it so the next
	// emitted message carries synthetic headers.
	if ev.Truncated() {
		st.pendingTruncated = true
		st.pendingDroppedBytes += uint64(ev.LenTotal) - uint64(ev.LenCaptured)
	}

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

		// Got a complete message. Tag with truncation metadata BEFORE the
		// envelope is built (so the synthetic headers ride along to the
		// witness + redactor + backend), then reset the per-message
		// counters for the next assembly cycle.
		if st.pendingTruncated {
			annotateTruncation(result, st.pendingDroppedBytes)
		}
		st.pendingTruncated = false
		st.pendingDroppedBytes = 0

		a.Out <- a.toPNT(st, key, result, now)
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
// downstream pipeline expects. When the resolver has produced a 4-tuple,
// IPs/ports are filled; otherwise they fall back to zero with the PID stashed
// in the Interface field for traceability.
//
// Direction mapping: for HTTPRequest (egress=write, ingress=read on server),
// SrcIP=local, DstIP=remote when we wrote (egress) — what we sent goes from
// us to them. For ingress (we received bytes), SrcIP=remote, DstIP=local.
func (a *Adapter) toPNT(st *flowState, key FlowKey, c akinet.ParsedNetworkContent, now time.Time) akinet.ParsedNetworkTraffic {
	pnt := akinet.ParsedNetworkTraffic{
		Content:         c,
		Interface:       st.ifaceTag,
		ObservationTime: st.firstSeen,
		FinalPacketTime: now,
	}
	if st.socketResolved {
		if key.Direction == DirEgress {
			pnt.SrcIP = st.localIP
			pnt.SrcPort = st.localPort
			pnt.DstIP = st.remoteIP
			pnt.DstPort = st.remotePort
		} else {
			pnt.SrcIP = st.remoteIP
			pnt.SrcPort = st.remotePort
			pnt.DstIP = st.localIP
			pnt.DstPort = st.localPort
		}
	} else {
		pnt.SrcIP = net.IPv4zero
		pnt.DstIP = net.IPv4zero
	}
	return pnt
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

// PreResolve caches a (pid, ssl_ctx, fd) → SocketInfo mapping. Called by
// the proactive resolver goroutine that scans the BPF ssl_ctx_to_fd map;
// lets late-arriving events whose socket has already closed still get IPs.
func (a *Adapter) PreResolve(pid uint32, sslCtx uint64, fd int32, info SocketInfo) {
	a.mu.Lock()
	a.resolved[resolvedKey{PID: pid, SSLCtx: sslCtx, FD: fd}] = info
	a.mu.Unlock()
}

// ForgetResolved drops cached resolutions for a PID (on PID exit).
func (a *Adapter) ForgetResolved(pid uint32) {
	a.mu.Lock()
	for k := range a.resolved {
		if k.PID == pid {
			delete(a.resolved, k)
		}
	}
	a.mu.Unlock()
}
