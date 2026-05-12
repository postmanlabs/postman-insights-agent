// SPDX-License-Identifier: Apache-2.0

package events

import (
	"sync"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/memview"
)

// Adapter feeds decrypted-byte events from a Reader into the existing akinet
// HTTP/HTTP2 parsers, producing akinet.ParsedNetworkTraffic records that are
// indistinguishable (downstream) from the pcap path's output.
//
// Per-flow state machine:
//
//   For each FlowKey (PID, SSLCtx, Direction):
//     - On first event, the adapter consults the TCPParserFactorySelector
//       (the same one pcap.Collect uses, registering HTTPRequestParserFactory
//       on ingress flows and HTTPResponseParserFactory on egress, OR using
//       the factory's "Accepts()" method on the first bytes).
//     - Subsequent events for the same flow are concatenated into the
//       current parser's input.
//     - When the parser returns a non-nil ParsedNetworkContent, we emit it
//       on the Out channel and discard any unused bytes (or start a new
//       parser if the factory indicates pipelining).
//
// The flow is forgotten after a configurable idle timeout (default 30s) or
// when we observe the SSL_shutdown event for the same SSLCtx.
//
// NOTE: This adapter is the minimal Phase 1 scaffold. The full Phase 2
// implementation must:
//   - Bound the per-flow buffer to defend against malformed streams that
//     never produce a complete parse.
//   - Track per-flow stats (total bytes, last-seen time) for telemetry.
//   - Synthesize plausible src/dst IP:port tuples by reading the SSL*->fd
//     mapping from /proc/<pid>/net/tcp (cf. OBI's get_conn_info_from_fd).
type Adapter struct {
	// FactorySelector picks the right parser for a new flow. Pass the same
	// selector the pcap path uses (akinet.TCPParserFactorySelector built
	// over akihttp.NewHTTPRequestParserFactory + NewHTTPResponseParserFactory
	// + akihttp2.NewHTTP2PrefaceParserFactory).
	FactorySelector akinet.TCPParserFactorySelector

	// Out receives one ParsedNetworkTraffic per parsed HTTP message. Typically
	// this is wired into the same channel pcap.Collect's collector reads from.
	Out chan<- akinet.ParsedNetworkTraffic

	mu    sync.Mutex
	flows map[FlowKey]*flowState
}

type flowState struct {
	parser     akinet.TCPParser
	lastSeen   time.Time
	firstSeen  time.Time
	totalBytes int
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
// PHASE 1 SCAFFOLD: this method shows the intended shape. Calling Parse()
// requires constructing a valid memview, a valid TCPBidiID for the flow, and
// proper seq/ack bookkeeping. The detailed wiring is deferred to Phase 2
// where we have the akinet types in hand and a working spike to validate
// against. See docs/https-capture-design.md §5.4 and §9 (Phase 2).
func (a *Adapter) Feed(ev *SSLEvent, monoEpoch time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := ev.Key()
	st, ok := a.flows[key]
	if !ok {
		st = &flowState{
			firstSeen: ev.Time(monoEpoch),
		}
		a.flows[key] = st
	}
	st.lastSeen = ev.Time(monoEpoch)
	st.totalBytes += int(ev.LenCaptured)

	// TODO(phase2): wire bytes into st.parser via memview + parser.Parse.
	// Pseudocode for the intended structure:
	//
	//   if st.parser == nil {
	//       factory := a.FactorySelector.Select(ev.Bytes(), false /*isEnd*/)
	//       if factory == nil { return /* not enough bytes yet; buffer */ }
	//       st.parser = factory.CreateParser(syntheticBidiID(key), 0, 0)
	//   }
	//   pnc, unused, consumed, err := st.parser.Parse(memview.New(ev.Bytes()), false)
	//   if err != nil { a.dropFlow(key); return }
	//   if pnc != nil {
	//       a.Out <- a.toParsedNetworkTraffic(key, st, pnc)
	//       st.parser = nil  // pipelined: next bytes start a new message
	//       _ = unused; _ = consumed
	//   }
	_ = memview.New(ev.Bytes()) // touch the import so it compiles
}

// GC removes flows idle for longer than `maxIdle`. Call periodically from a
// goroutine driven by a time.Ticker.
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

// Snapshot returns counts for telemetry without holding the lock long.
func (a *Adapter) Snapshot() (numFlows int, totalBytes int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	numFlows = len(a.flows)
	for _, st := range a.flows {
		totalBytes += st.totalBytes
	}
	return
}
