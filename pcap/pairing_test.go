package pcap

import (
	"testing"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/akinet"
	akihttp "github.com/akitasoftware/akita-libs/akinet/http"
	"github.com/akitasoftware/akita-libs/buffer_pool"
	"github.com/akitasoftware/akita-libs/memview"
	"github.com/akitasoftware/akita-libs/tags"
	"github.com/akitasoftware/go-utils/optionals"
	"github.com/google/gopacket"
	"github.com/google/gopacket/reassembly"
	"github.com/postmanlabs/postman-insights-agent/capturestats"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
)

// fakeHTTPRequestFactory has the same Name() as akinet/http's real HTTP
// request parser factory, without needing a buffer pool, so pairSeqForFactory
// can be tested in isolation from real HTTP parsing.
type fakeHTTPRequestFactory struct{}

func (fakeHTTPRequestFactory) Name() string { return httpRequestParserFactoryName }

func (fakeHTTPRequestFactory) Accepts(input memview.MemView, isEnd bool) (akinet.AcceptDecision, int64) {
	return akinet.Reject, 0
}

func (fakeHTTPRequestFactory) CreateParser(id akinet.TCPBidiID, seq, ack reassembly.Sequence) akinet.TCPParser {
	return nil
}

// TestPairSequencer exercises the FIFO pairing queue directly: requests push
// an index, responses pop the oldest unmatched one, in order -- including
// the pipelined case where two requests arrive before either response.
func TestPairSequencer(t *testing.T) {
	p := newPairSequencer()
	req := fakeHTTPRequestFactory{}
	notReq := princeParserFactory{} // any factory whose Name() isn't the HTTP request factory's

	// Simple case: request then its response.
	r0 := p.pairSeqForFactory(req)
	s0 := p.pairSeqForFactory(notReq)
	if r0 != s0 {
		t.Errorf("expected first response to pair with first request: req=%v resp=%v", r0, s0)
	}

	// Pipelined case: two requests arrive before either response. FIFO
	// ordering must still pair them correctly.
	r1 := p.pairSeqForFactory(req)
	r2 := p.pairSeqForFactory(req)
	s1 := p.pairSeqForFactory(notReq)
	s2 := p.pairSeqForFactory(notReq)

	if r1 != s1 {
		t.Errorf("expected second request to pair with first of the two pending responses: req=%v resp=%v", r1, s1)
	}
	if r2 != s2 {
		t.Errorf("expected third request to pair with second of the two pending responses: req=%v resp=%v", r2, s2)
	}
	if r1 == r2 {
		t.Errorf("expected the two pipelined requests to get distinct indices, both got %v", r1)
	}
}

// setupPairingTestParser wires up a NetworkTrafficParser with real HTTP/1.x
// parser factories (not the fake prince/pineapple protocols used elsewhere
// in this package), and filters its output down to just the parsed HTTP
// requests and responses.
func setupPairingTestParser(useSyntheticPairing bool, pkts []gopacket.Packet, signalClose <-chan struct{}, pool buffer_pool.BufferPool) (<-chan akinet.ParsedNetworkTraffic, error) {
	p := NewNetworkTrafficParser(akid.GenerateServiceID(), map[tags.Key]string{}, 1.0, telemetry.Default(), capturestats.New())
	p.pcap = fakePcap(pkts)
	p.clock = &fakeClock{testTime}
	p.useSyntheticPairing = useSyntheticPairing

	rawOut, err := p.ParseFromInterface("dummy0", "", optionals.None[string](), signalClose,
		akihttp.NewHTTPRequestParserFactory(pool),
		akihttp.NewHTTPResponseParserFactory(pool),
	)
	if err != nil {
		return nil, err
	}

	out := make(chan akinet.ParsedNetworkTraffic)
	go func() {
		defer close(out)
		for pkt := range rawOut {
			switch pkt.Content.(type) {
			case akinet.HTTPRequest, akinet.HTTPResponse:
				out <- pkt
			default:
				// e.g. TCPPacketMetadata today; release on principle so this
				// doesn't start leaking if a content type that does hold a
				// buffer gets added to the filter's default case later.
				pkt.Content.ReleaseBuffers()
			}
		}
	}()
	return out, nil
}

// TestSyntheticTCPPairingFixesKeepAliveMismatch reproduces the pairing bug
// end to end (real TCP packets, real HTTP/1.x parsing, no live traffic
// capture needed) and shows the fix resolves it.
//
// Two HTTP request/response exchanges happen on one keep-alive connection.
// The second request's ACK is deliberately a few bytes short of fully
// acknowledging the first response -- a client that fires its next request
// slightly before its TCP stack has acked all of the previous response,
// which is what breaks the real seq/ack pairing on a busy connection (see
// the requestKey comment in trace/rate_limit.go, and pairing.go).
//
// The first exchange pairs correctly either way, since nothing preceded it.
// The second exchange is where the two pairing strategies diverge: with the
// existing seq/ack pairing it MUST mismatch (reproducing the drop), and with
// synthetic pairing enabled it MUST match (the fix).
func TestSyntheticTCPPairingFixesKeepAliveMismatch(t *testing.T) {
	pool, err := buffer_pool.MakeBufferPool(1024*1024, 4*1024)
	if err != nil {
		t.Fatalf("failed to create buffer pool: %v", err)
	}

	const (
		clientSeq0   = 1000
		serverSeq0   = 2000
		ackShortfall = 3 // bytes of resp1 that req2's ACK fails to cover
	)
	req1 := []byte("GET /a HTTP/1.1\r\nHost: x.com\r\nContent-Length: 0\r\n\r\n")
	resp1 := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	req2 := []byte("GET /b HTTP/1.1\r\nHost: x.com\r\nContent-Length: 0\r\n\r\n")
	resp2 := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

	clientSeqAfterReq1 := uint32(clientSeq0 + len(req1))
	serverSeqAfterResp1 := uint32(serverSeq0 + len(resp1))

	makePackets := func() []gopacket.Packet {
		return []gopacket.Packet{
			// Exchange 1: req1's ACK (serverSeq0) equals resp1's SEQ -- the
			// "nothing else in flight yet" case that always pairs.
			CreatePacketWithSeqAndAck(ip1, ip2, port1, port2, req1, clientSeq0, serverSeq0),
			CreatePacketWithSeqAndAck(ip2, ip1, port2, port1, resp1, serverSeq0, clientSeqAfterReq1),

			// Exchange 2: req2's ACK is short of resp2's SEQ by ackShortfall
			// bytes, reproducing the keep-alive skew.
			CreatePacketWithSeqAndAck(ip1, ip2, port1, port2, req2, clientSeqAfterReq1, serverSeqAfterResp1-ackShortfall),
			CreatePacketWithSeqAndAck(ip2, ip1, port2, port1, resp2, serverSeqAfterResp1, clientSeqAfterReq1+uint32(len(req2))),
		}
	}

	collect := func(useSyntheticPairing bool) (reqs []akinet.HTTPRequest, resps []akinet.HTTPResponse) {
		closeChan := make(chan struct{})
		defer close(closeChan)

		out, err := setupPairingTestParser(useSyntheticPairing, makePackets(), closeChan, pool)
		if err != nil {
			t.Fatalf("failed to set up parser: %v", err)
		}

		for pkt := range out {
			switch c := pkt.Content.(type) {
			case akinet.HTTPRequest:
				reqs = append(reqs, c)
			case akinet.HTTPResponse:
				resps = append(resps, c)
			}
			pkt.Content.ReleaseBuffers()
		}
		return reqs, resps
	}

	t.Run("existing seq/ack pairing: second exchange mismatches", func(t *testing.T) {
		reqs, resps := collect(false)
		if len(reqs) != 2 || len(resps) != 2 {
			t.Fatalf("expected 2 requests and 2 responses, got %d requests and %d responses", len(reqs), len(resps))
		}
		if reqs[0].Seq != resps[0].Seq {
			t.Errorf("expected first exchange to pair (nothing preceded it): request.Seq=%d response.Seq=%d", reqs[0].Seq, resps[0].Seq)
		}
		if reqs[1].Seq == resps[1].Seq {
			t.Errorf("expected second exchange to MISMATCH under existing seq/ack pairing (this is the bug we're fixing), but request.Seq=%d == response.Seq=%d", reqs[1].Seq, resps[1].Seq)
		}
	})

	t.Run("synthetic pairing: both exchanges match", func(t *testing.T) {
		reqs, resps := collect(true)
		if len(reqs) != 2 || len(resps) != 2 {
			t.Fatalf("expected 2 requests and 2 responses, got %d requests and %d responses", len(reqs), len(resps))
		}
		if reqs[0].Seq != resps[0].Seq {
			t.Errorf("expected first exchange to pair: request.Seq=%d response.Seq=%d", reqs[0].Seq, resps[0].Seq)
		}
		if reqs[1].Seq != resps[1].Seq {
			t.Errorf("expected second exchange to MATCH under synthetic pairing (this is the fix), but request.Seq=%d != response.Seq=%d", reqs[1].Seq, resps[1].Seq)
		}
	})
}
