// SPDX-License-Identifier: Apache-2.0

package events

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/memview"
	"github.com/google/gopacket/reassembly"
	"github.com/google/uuid"
)

// MaxPendingPerFlow caps the bytes we will buffer for a single flow while
// waiting for the FactorySelector to commit to a parser. Without this cap,
// a malformed or pathological stream that never produces a parseable HTTP
// message could grow unbounded. The value mirrors OBI's `large_buffers`
// limit at the user-space side.
const MaxPendingPerFlow = 1 * 1024 * 1024

// Adapter feeds decrypted-byte events from a Reader into the existing akinet
// HTTP/HTTP2 parsers, producing akinet.ParsedNetworkTraffic records that are
// indistinguishable (downstream) from the pcap path's output.
//
// Per-flow state machine:
//
//	For each FlowKey (PID, SSLCtx, Direction):
//	  - Incoming bytes are appended to a per-flow pending buffer.
//	  - With no current parser: consult the FactorySelector.
//	      Accept       → create parser, hand pending bytes to Parse.
//	      NeedMoreData → keep pending bytes, return.
//	      Reject       → drop the flow permanently.
//	  - With a current parser: call Parse(pending, false). On a non-nil
//	    result, emit a ParsedNetworkTraffic on Out, clear the parser, and
//	    re-enter the "no parser" branch with any unused tail bytes (this
//	    handles HTTP keep-alive pipelining: one TCP/SSL flow carrying
//	    N back-to-back requests or responses).
//
// The flow is forgotten after a configurable idle timeout (default 30s) or
// when an SSL_shutdown event arrives.
//
// IP/port synthesis: when a Resolver is set, SrcIP/DstIP/ports are filled from
// /proc/<pid>/net/tcp via the SSL*→fd map. When Resolver is nil, IPs are left
// zero and "ebpf-pid-<N>" is stored in the Interface field for traceability.
// See docs/https-capture-design.md §5.4.
type Adapter struct {
	// FactorySelector picks the right parser for a new flow. Pass the same
	// selector the pcap path uses.
	FactorySelector akinet.TCPParserFactorySelector

	// Out receives one ParsedNetworkTraffic per parsed HTTP message.
	Out chan<- akinet.ParsedNetworkTraffic

	// Resolver, when non-nil, is consulted to fill SrcIP/DstIP/SrcPort/DstPort
	// on emitted ParsedNetworkTraffic from the (pid, fd) carried in each
	// SSLEvent. When nil, IPs are left zero.
	Resolver *Resolver

	mu    sync.Mutex
	flows map[FlowKey]*flowState

	// conns holds per-TLS-connection state shared by ingress and egress
	// FlowKeys with the same (PID, SSLCtx). Mirrors pcap's single bidiID per
	// TCP connection in tcpStream.
	conns map[connKey]*tlsConnState

	// resolved caches socket tuples by (pid, ssl_ctx, fd).
	resolved map[resolvedKey]SocketInfo

	// Counters exported for telemetry / tests.
	MessagesEmitted uint64
	FlowsDropped    uint64
}

// connKey identifies a TLS connection (both directions).
type connKey struct {
	PID    uint32
	SSLCtx uint64
}

// tlsConnState is shared by all FlowKeys on the same TLS connection.
type tlsConnState struct {
	bidiID akinet.TCPBidiID

	// Synthetic pair indices substitute for TCP seq/ack in the akihttp
	// parser (request Seq = ack, response Seq = seq). Requests push their
	// index onto unmatchedRequests; responses pop FIFO so pipelined HTTP/1.1
	// still pairs correctly.
	nextPairIdx       int
	unmatchedRequests []int
	activeFlowCount   int

	// Resolved 4-tuple shared by ingress and egress on this TLS connection.
	socketResolved bool
	localIP        net.IP
	localPort      int
	remoteIP       net.IP
	remotePort     int
}

func (c *tlsConnState) pairSeqForFactory(factory akinet.TCPParserFactory) reassembly.Sequence {
	if isHTTPRequestParserFactory(factory) {
		idx := c.nextPairIdx
		c.nextPairIdx++
		c.unmatchedRequests = append(c.unmatchedRequests, idx)
		return reassembly.Sequence(idx)
	}
	idx := c.nextPairIdx
	if len(c.unmatchedRequests) > 0 {
		idx = c.unmatchedRequests[0]
		c.unmatchedRequests = c.unmatchedRequests[1:]
	} else {
		c.nextPairIdx++
	}
	return reassembly.Sequence(idx)
}

func isHTTPRequestParserFactory(factory akinet.TCPParserFactory) bool {
	return factory.Name() == "HTTP/1.x Request Parser Factory"
}

type flowState struct {
	parser akinet.TCPParser
	pending memview.MemView
	conn    *tlsConnState
	// firstSeen is when this flow was first observed (connection-level; used as
	// a fallback and for GC). msgStart is when the CURRENT message's first byte
	// arrived — this is what a witness's ObservationTime must use, otherwise
	// every message on a keep-alive flow inherits the flow's first-ever
	// timestamp (causing negative processing latency and wrong witness times).
	firstSeen time.Time
	msgStart  time.Time
	lastSeen  time.Time
	totalIn   int  // total bytes ever observed on this flow
	dropped   bool // permanent: malformed or oversized
	ifaceTag  string

	// HTTP/2 path: if h2 != nil, all bytes for this flow are routed to
	// the stateful HTTP/2 decoder instead of the akinet single-use parser.
	// Detection happens on the first bytes via IsHTTP2Preface.
	h2 *h2State

	pid uint32 // for Forget on flow close
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
		conns:    make(map[connKey]*tlsConnState),
		resolved: make(map[resolvedKey]SocketInfo),
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
	ck := connKey{PID: ev.PID, SSLCtx: ev.SSLCtx}
	conn := a.conns[ck]
	if conn == nil {
		conn = &tlsConnState{bidiID: akinet.TCPBidiID(uuid.New())}
		a.conns[ck] = conn
	}

	st := a.flows[key]
	if st == nil {
		st = &flowState{
			firstSeen: ev.Time(monoEpoch),
			conn:      conn,
			ifaceTag:  fmt.Sprintf("ebpf-pid-%d", ev.PID),
			pid:       ev.PID,
		}
		a.flows[key] = st
		conn.activeFlowCount++
	}
	if st.dropped {
		return
	}

	// Lazily resolve the 4-tuple from (pid, fd) when available.
	a.tryResolveConn(conn, ev)
	st.lastSeen = ev.Time(monoEpoch)
	st.totalIn += int(ev.LenCaptured)

	// If we've already committed this flow to the HTTP/2 path, stay there.
	if st.h2 != nil {
		for _, pnt := range st.h2.feed(ev.Bytes(), ev.Time(monoEpoch), st.ifaceTag) {
			a.emitH2PNT(key, st, pnt)
		}
		return
	}

	// Detect HTTP/2 on the first bytes we see on this flow.
	// Two paths: full preface (when we attach before the connection opens)
	// or a recognisable frame header (when we attach mid-connection, which is
	// the common case for gotls because the TLS handshake + preface complete
	// before the uprobes catch their first non-handshake call).
	if st.pending.Len() == 0 && (IsHTTP2Preface(ev.Bytes()) || IsHTTP2Frame(ev.Bytes())) {
		st.h2 = newH2State(st.conn.bidiID)
		for _, pnt := range st.h2.feed(ev.Bytes(), ev.Time(monoEpoch), st.ifaceTag) {
			a.emitH2PNT(key, st, pnt)
		}
		return
	}

	// Mark the start of a new message: when there are no buffered bytes for an
	// in-progress message, this event carries the first byte of the next one.
	if st.pending.Len() == 0 {
		st.msgStart = ev.Time(monoEpoch)
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
				// Synthetic seq/ack mirror pcap: request PairKey uses ack,
				// response PairKey uses seq, both equal to the same pair index.
				pairSeq := st.conn.pairSeqForFactory(factory)
				st.parser = factory.CreateParser(st.conn.bidiID, pairSeq, pairSeq)
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
		a.Out <- a.toPNT(st, key, result, now)
		a.MessagesEmitted++
		st.parser = nil
		st.pending = unused
		// Any leftover (pipelined) bytes belong to the next message, and they
		// arrived at "now" — start its clock here so it doesn't inherit this
		// message's start time.
		if st.pending.Len() > 0 {
			st.msgStart = now
		}
	}
}

func (a *Adapter) emitH2PNT(key FlowKey, st *flowState, pnt akinet.ParsedNetworkTraffic) {
	if st.conn.socketResolved {
		if key.Direction == DirEgress {
			pnt.SrcIP, pnt.SrcPort = st.conn.localIP, st.conn.localPort
			pnt.DstIP, pnt.DstPort = st.conn.remoteIP, st.conn.remotePort
		} else {
			pnt.SrcIP, pnt.SrcPort = st.conn.remoteIP, st.conn.remotePort
			pnt.DstIP, pnt.DstPort = st.conn.localIP, st.conn.localPort
		}
	}
	if req, ok := pnt.Content.(akinet.HTTPRequest); ok {
		enrichHTTPRequestURL(&req, key.Direction, st.conn.localIP, st.conn.localPort, st.conn.remoteIP, st.conn.remotePort)
		pnt.Content = req
	}
	pnt.Direction = directionForPair(pnt.Content, key.Direction)
	a.Out <- pnt
	a.MessagesEmitted++
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
	// ObservationTime is the start of THIS message (msgStart), not the flow's
	// first-ever message (firstSeen) — otherwise every message on a keep-alive
	// connection inherits the flow's creation time, producing negative
	// processing latency and incorrect witness timestamps. Fall back to
	// firstSeen if msgStart was never set.
	obsTime := st.msgStart
	if obsTime.IsZero() {
		obsTime = st.firstSeen
	}
	pnt := akinet.ParsedNetworkTraffic{
		Content:         c,
		Interface:       st.ifaceTag,
		ObservationTime: obsTime,
		FinalPacketTime: now,
	}
	if st.conn.socketResolved {
		if key.Direction == DirEgress {
			pnt.SrcIP = st.conn.localIP
			pnt.SrcPort = st.conn.localPort
			pnt.DstIP = st.conn.remoteIP
			pnt.DstPort = st.conn.remotePort
		} else {
			pnt.SrcIP = st.conn.remoteIP
			pnt.SrcPort = st.conn.remotePort
			pnt.DstIP = st.conn.localIP
			pnt.DstPort = st.conn.localPort
		}
	} else {
		pnt.SrcIP = net.IPv4zero
		pnt.DstIP = net.IPv4zero
	}
	pnt.Direction = directionForPair(c, key.Direction)
	return pnt
}

// directionForPair maps the wire direction of an SSL call (ingress = SSL_read,
// egress = SSL_write) and the HTTP message kind to the service-relative
// direction of the whole request/response pair:
//
//	request received (ingress)  -> service is the server -> inbound
//	request sent     (egress)   -> service is the client -> outbound
//	response received (ingress) -> service is the client -> outbound
//	response sent     (egress)  -> service is the server -> inbound
//
// Both the request and the response of a pair therefore resolve to the same
// direction, so it does not matter which arrives first.
func directionForPair(content akinet.ParsedNetworkContent, wireDir uint8) akinet.NetTrafficDirection {
	ingress := wireDir == DirIngress
	switch content.(type) {
	case akinet.HTTPRequest:
		if ingress {
			return akinet.DirectionInbound
		}
		return akinet.DirectionOutbound
	case akinet.HTTPResponse:
		if ingress {
			return akinet.DirectionOutbound
		}
		return akinet.DirectionInbound
	default:
		return akinet.DirectionUnknown
	}
}

// GC removes flows idle for longer than `maxIdle`. Call periodically.
func (a *Adapter) GC(now time.Time, maxIdle time.Duration) int {
	a.mu.Lock()
	defer a.mu.Unlock()

	dropped := 0
	for k, st := range a.flows {
		if now.Sub(st.lastSeen) > maxIdle {
			a.forgetFlow(k, st)
			dropped++
		}
	}
	return dropped
}

func (a *Adapter) forgetFlow(key FlowKey, st *flowState) {
	delete(a.flows, key)
	st.conn.activeFlowCount--
	if st.conn.activeFlowCount == 0 {
		delete(a.conns, connKey{PID: key.PID, SSLCtx: key.SSLCtx})
	}
}

// CloseFlow forgets state for one flow. Called when an SSL_shutdown event
// arrives or the parent process exits.
func (a *Adapter) CloseFlow(key FlowKey) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if st, ok := a.flows[key]; ok {
		a.forgetFlow(key, st)
	}
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
	if conn, ok := a.conns[connKey{PID: pid, SSLCtx: sslCtx}]; ok {
		a.applySocketInfo(conn, info)
	}
	a.mu.Unlock()
}

func (a *Adapter) tryResolveConn(conn *tlsConnState, ev *SSLEvent) {
	if conn.socketResolved || a.Resolver == nil || ev.FD < 0 {
		return
	}
	rk := resolvedKey{PID: ev.PID, SSLCtx: ev.SSLCtx, FD: ev.FD}
	if info, ok := a.resolved[rk]; ok {
		a.applySocketInfo(conn, info)
		return
	}
	if info, err := a.Resolver.Resolve(ev.PID, ev.FD); err == nil {
		a.resolved[rk] = info
		a.applySocketInfo(conn, info)
	}
}

func (a *Adapter) applySocketInfo(conn *tlsConnState, info SocketInfo) {
	conn.localIP = info.LocalIP
	conn.localPort = info.LocalPort
	conn.remoteIP = info.RemoteIP
	conn.remotePort = info.RemotePort
	conn.socketResolved = true
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
