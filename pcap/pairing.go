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
// This flag switches to tracking message emission order per connection
// instead of TCP byte offsets (the eBPF path uses the same FIFO idea). It is
// a flag rather than the default so it can be validated against real traffic
// first; once confirmed, remove the flag and the old seq/ack path rather
// than keeping both as permanent configuration.
//
// FIFO ordinals are stamped when a message is successfully emitted, not when
// a parser Accepts the first bytes. Accept-time allocation used to leave the
// queue permanently skewed after a failed/abandoned parse.
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
// Ordinals must be allocated only when a message is successfully emitted
// (stampSyntheticPairSeq), not when a parser factory Accepts the first
// bytes. Accept-time allocation permanently skews the FIFO if that parse
// later fails or the message is discarded -- every subsequent exchange on
// the keep-alive connection then mismatches at rate-limit / pairCache.
//
// Not synchronized: like the rest of tcpFlow/tcpStream, a pairSequencer is
// only ever touched by the single goroutine that drives TCP reassembly for
// the interface owning this connection (see NetworkTrafficParser.ParseFromInterface).
//
// Only reached for HTTP/1.x request/response messages. TLS, HTTP/2-preface,
// and any other factory keep the real ctx.seq/ctx.ack unconditionally.
type pairSequencer struct {
	nextPairIdx       int
	unmatchedRequests []int
}

func newPairSequencer() *pairSequencer {
	return &pairSequencer{}
}

func (p *pairSequencer) pairSeqForRequest() reassembly.Sequence {
	idx := p.nextPairIdx
	p.nextPairIdx++
	p.unmatchedRequests = append(p.unmatchedRequests, idx)
	return reassembly.Sequence(idx)
}

func (p *pairSequencer) pairSeqForResponse() reassembly.Sequence {
	idx := p.nextPairIdx
	if len(p.unmatchedRequests) > 0 {
		idx = p.unmatchedRequests[0]
		p.unmatchedRequests = p.unmatchedRequests[1:]
	} else {
		p.nextPairIdx++
	}
	return reassembly.Sequence(idx)
}

// stampSyntheticPairSeq overwrites HTTP request/response Seq with a FIFO
// ordinal at emit time. Non-HTTP content is returned unchanged.
func (p *pairSequencer) stampSyntheticPairSeq(pnc akinet.ParsedNetworkContent) akinet.ParsedNetworkContent {
	if p == nil {
		return pnc
	}
	switch c := pnc.(type) {
	case akinet.HTTPRequest:
		c.Seq = int(p.pairSeqForRequest())
		return c
	case akinet.HTTPResponse:
		c.Seq = int(p.pairSeqForResponse())
		return c
	default:
		return pnc
	}
}
