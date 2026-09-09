package pcap

import (
	"os"
	"strconv"

	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/google/gopacket/reassembly"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// Set POSTMAN_INSIGHTS_AGENT_SYNTHETIC_TCP_PAIRING=true to pair HTTP/1.x
// requests and responses using a synthetic per-connection FIFO ordinal
// instead of their real TCP seq/ack numbers. Off by default.
//
// The existing pairing (tcpFlow.reassembled's fact.CreateParser(f.bidiID,
// ctx.seq, ctx.ack)) relies on the ACK on a request's first segment being
// equal to the SEQ of its response's first segment, which akita-libs'
// http.newHTTPParser uses as the pairing key (request.Seq = ack,
// response.Seq = seq -- see akinet/http/parser.go). That equality only holds
// if nothing else was in flight on the connection; see the requestKey
// comment in trace/rate_limit.go for the failure mode this causes
// (responses dropped as ResponsesDroppedNoMatchingRequest, which surfaces at
// the back end as a missing_status_code witness).
//
// This flag switches to the fix already proven on the eBPF capture path
// (ebpf/events/adapter.go's tlsConnState.pairSeqForFactory): track message
// arrival order per connection instead of TCP byte offsets. It is a flag
// rather than the default so it can be validated against real traffic
// first; once confirmed, remove the flag and the old seq/ack path rather
// than keeping both as permanent configuration.
const syntheticTCPPairingEnvVar = "POSTMAN_INSIGHTS_AGENT_SYNTHETIC_TCP_PAIRING"

func syntheticTCPPairingEnabled() bool {
	v, present := os.LookupEnv(syntheticTCPPairingEnvVar)
	if !present {
		return false
	}
	enabled, err := strconv.ParseBool(v)
	if err != nil {
		printer.Warningf("Could not parse %s value %q, defaulting to disabled: %v\n",
			syntheticTCPPairingEnvVar, v, err)
		return false
	}
	return enabled
}

// pairSequencer generates synthetic pairing sequence numbers shared by both
// directions of one TCP connection (see tcpStream.pairSeq), used in place of
// real TCP seq/ack numbers when synthetic TCP pairing is enabled.
//
// Mirrors ebpf/events/adapter.go's tlsConnState.pairSeqForFactory: HTTP
// requests push their index onto a FIFO queue, responses pop the oldest
// unmatched index, so pipelined or overlapping HTTP/1.1 exchanges on the
// same connection still pair correctly regardless of what TCP acked when.
//
// Ordinals are allocated when a parser factory Accepts the first bytes
// (pairSeqForFactory). If that parse later fails or is abandoned, call
// rollbackPairSeq so the FIFO does not stay permanently skewed.
//
// Not synchronized: like the rest of tcpFlow/tcpStream, a pairSequencer is
// only ever touched by the single goroutine that drives TCP reassembly for
// the interface owning this connection (see NetworkTrafficParser.ParseFromInterface).
//
// Only reached for HTTP/1.x request/response factories -- see
// isHTTPParserFactory and its call site in tcpFlow.reassembled. TLS,
// HTTP/2-preface, and any other factory keep the real ctx.seq/ctx.ack
// unconditionally, even when synthetic pairing is enabled, since this fix
// only concerns HTTP/1.x pairing and those factories' CreateParser
// implementations don't use their seq/ack params at all today.
type pairSequencer struct {
	nextPairIdx       int
	unmatchedRequests []int
}

func newPairSequencer() *pairSequencer {
	return &pairSequencer{}
}

// pairAllocKind records how an Accept-time ordinal was taken from the FIFO so
// rollbackPairSeq can undo it if the parse never emits.
type pairAllocKind int

const (
	pairAllocNone pairAllocKind = iota
	pairAllocRequestPush
	pairAllocResponsePop
	pairAllocResponseInvent
)

func (p *pairSequencer) pairSeqForFactory(factory akinet.TCPParserFactory) (reassembly.Sequence, pairAllocKind) {
	if isHTTPRequestParserFactory(factory) {
		idx := p.nextPairIdx
		p.nextPairIdx++
		p.unmatchedRequests = append(p.unmatchedRequests, idx)
		return reassembly.Sequence(idx), pairAllocRequestPush
	}

	if len(p.unmatchedRequests) > 0 {
		idx := p.unmatchedRequests[0]
		p.unmatchedRequests = p.unmatchedRequests[1:]
		return reassembly.Sequence(idx), pairAllocResponsePop
	}
	idx := p.nextPairIdx
	p.nextPairIdx++
	return reassembly.Sequence(idx), pairAllocResponseInvent
}

// rollbackPairSeq undoes an Accept-time allocation when the parser fails or is
// abandoned before a successful emit. Safe no-op for pairAllocNone.
func (p *pairSequencer) rollbackPairSeq(seq reassembly.Sequence, kind pairAllocKind) {
	if p == nil {
		return
	}
	idx := int(seq)
	switch kind {
	case pairAllocRequestPush:
		// Single-goroutine reassembly: the abandoned request is still the last
		// unmatched entry if nothing else Accept'd on this connection since.
		if n := len(p.unmatchedRequests); n > 0 && p.unmatchedRequests[n-1] == idx {
			p.unmatchedRequests = p.unmatchedRequests[:n-1]
		} else {
			// Remove by value if ordering was disturbed (defensive).
			for i, v := range p.unmatchedRequests {
				if v == idx {
					p.unmatchedRequests = append(p.unmatchedRequests[:i], p.unmatchedRequests[i+1:]...)
					break
				}
			}
		}
		if p.nextPairIdx == idx+1 {
			p.nextPairIdx = idx
		}
	case pairAllocResponsePop:
		p.unmatchedRequests = append([]int{idx}, p.unmatchedRequests...)
	case pairAllocResponseInvent:
		if p.nextPairIdx == idx+1 {
			p.nextPairIdx = idx
		}
	}
}

func isHTTPRequestParserFactory(factory akinet.TCPParserFactory) bool {
	return factory.Name() == httpRequestParserFactoryName
}

// isHTTPParserFactory reports whether factory is the HTTP/1.x request or
// response parser factory -- the only two whose pairing key
// (akinet/http/parser.go's newHTTPParser) is derived from seq/ack. This
// gates which factories get the synthetic ordinal substituted in for
// ctx.seq/ctx.ack at pairSequencer's call site in tcpFlow.reassembled.
func isHTTPParserFactory(factory akinet.TCPParserFactory) bool {
	name := factory.Name()
	return name == httpRequestParserFactoryName || name == httpResponseParserFactoryName
}
