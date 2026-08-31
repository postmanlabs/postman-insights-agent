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
// Not synchronized: like the rest of tcpFlow/tcpStream, a pairSequencer is
// only ever touched by the single goroutine that drives TCP reassembly for
// the interface owning this connection (see NetworkTrafficParser.ParseFromInterface).
//
// Non-HTTP-request factories (HTTP response, TLS handshake, HTTP/2 preface)
// all fall into the "pop" branch below. That's harmless for TLS and HTTP/2
// preface: pcap never extracts HTTP witnesses from those (TLS-encrypted
// traffic is opaque to pcap, and the HTTP/2 preface parser is a one-time
// sink), so the one counter value they consume is never compared against
// anything.
type pairSequencer struct {
	nextPairIdx       int
	unmatchedRequests []int
}

func newPairSequencer() *pairSequencer {
	return &pairSequencer{}
}

func (p *pairSequencer) pairSeqForFactory(factory akinet.TCPParserFactory) reassembly.Sequence {
	if isHTTPRequestParserFactory(factory) {
		idx := p.nextPairIdx
		p.nextPairIdx++
		p.unmatchedRequests = append(p.unmatchedRequests, idx)
		return reassembly.Sequence(idx)
	}

	idx := p.nextPairIdx
	if len(p.unmatchedRequests) > 0 {
		idx = p.unmatchedRequests[0]
		p.unmatchedRequests = p.unmatchedRequests[1:]
	} else {
		p.nextPairIdx++
	}
	return reassembly.Sequence(idx)
}

func isHTTPRequestParserFactory(factory akinet.TCPParserFactory) bool {
	return factory.Name() == "HTTP/1.x Request Parser Factory"
}
