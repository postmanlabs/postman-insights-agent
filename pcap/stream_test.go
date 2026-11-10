package pcap

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	akihttp "github.com/akitasoftware/akita-libs/akinet/http"
	"github.com/akitasoftware/akita-libs/buffer_pool"
	"github.com/akitasoftware/akita-libs/memview"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/google/uuid"
	"github.com/postmanlabs/postman-insights-agent/capturestats"
)

var (
	dummyIP1           = net.ParseIP("127.0.0.1")
	dummyIP2           = net.ParseIP("10.0.0.1")
	dummyNetFlow       = gopacket.NewFlow(layers.EndpointIPv4, dummyIP1, dummyIP2)
	dummyTCPPacketFlow = gopacket.NewFlow(layers.EndpointTCPPort, []byte{0, 80}, []byte{0, 81})
	dummyBidiID        = akinet.TCPBidiID(uuid.New())
)

func dummyPNT(c akinet.ParsedNetworkContent) akinet.ParsedNetworkTraffic {
	return akinet.ParsedNetworkTraffic{
		SrcIP:           dummyIP1,
		SrcPort:         80,
		DstIP:           dummyIP2,
		DstPort:         81,
		Content:         c,
		ObservationTime: testTime,
		FinalPacketTime: testTime,
	}
}

type fakeScatterGather struct {
	saved, data memview.MemView
	keepFrom    int
	isEnd       bool
	nilContext  bool
}

func (sg fakeScatterGather) Lengths() (int, int) {
	return int(sg.saved.Len() + sg.data.Len()), int(sg.saved.Len())
}

func (sg fakeScatterGather) Fetch(l int) []byte {
	all := sg.saved.DeepCopy()
	all.Append(sg.data)
	return []byte(all.SubView(0, int64(l)).String())
}

func (sg *fakeScatterGather) KeepFrom(k int) {
	sg.keepFrom = k
}

func (sg fakeScatterGather) CaptureInfo(offset int) gopacket.CaptureInfo {
	return gopacket.CaptureInfo{Timestamp: testTime}
}

func (sg fakeScatterGather) AssemblerContext(offset int) reassembly.AssemblerContext {
	if sg.nilContext {
		return nil
	}
	return &assemblerCtxWithSeq{ci: sg.CaptureInfo(offset)}
}

func (sg fakeScatterGather) Info() (direction reassembly.TCPFlowDirection, start bool, end bool, skip int) {
	return reassembly.TCPFlowDirection(false), false, sg.isEnd, 0
}

func (sg fakeScatterGather) Stats() reassembly.TCPAssemblyStats {
	panic("unimplemented")
}

// chanSink is a ParsedNetworkTrafficSink that blocks on a channel, so tests
// see every PNT instead of having it dropped when the buffer is full.
type chanSink chan akinet.ParsedNetworkTraffic

func (c chanSink) Enqueue(t akinet.ParsedNetworkTraffic) {
	c <- t
}

func newTestTCPFlow(out chan akinet.ParsedNetworkTraffic, fs akinet.TCPParserFactorySelector, stats *capturestats.Stats, telemetryCountReporter func(string, uint64)) *tcpFlow {
	s := newTCPStream(&fakeClock{testTime}, dummyNetFlow, chanSink(out), fs, stats, false, nil, telemetryCountReporter, "")
	s.bidiID = dummyBidiID
	return newTCPFlow(s, dummyNetFlow, dummyTCPPacketFlow, nil)
}

type tcpFlowTestCase struct {
	name     string
	inputs   []string
	expected []akinet.ParsedNetworkTraffic
}

func runTCPFlowTestCase(c tcpFlowTestCase) error {
	sg := &fakeScatterGather{}

	out := make(chan akinet.ParsedNetworkTraffic, 100) // buffer a lot so it doesn't block
	fs := akinet.TCPParserFactorySelector([]akinet.TCPParserFactory{
		princeParserFactory{},
		pineappleParserFactory{},
	})
	f := newTestTCPFlow(out, fs, capturestats.New(), nil)

	for i, input := range c.inputs {
		sg.data = memview.New([]byte(input))
		sg.keepFrom = -1
		sg.isEnd = i == len(c.inputs)-1

		f.reassembled(sg, sg.AssemblerContext(0))

		// ScatterGather bookkeeping
		if sg.keepFrom >= 0 {
			all := sg.saved.DeepCopy()
			all.Append(sg.data)
			sg.saved = all.SubView(int64(sg.keepFrom), all.Len())
		} else {
			sg.saved.Clear()
		}
		sg.data.Clear()
	}
	f.reassemblyComplete()

	if len(c.expected) == 0 && len(out) > 0 {
		return fmt.Errorf("[%s] expected no results, got %d, input=%s", c.name, len(out), c.inputs)
	}

	actual := make([]akinet.ParsedNetworkTraffic, 0, len(c.expected))
	for i := 0; i < len(c.expected); i++ {
		select {
		case pnc := <-out:
			actual = append(actual, pnc)
		case <-time.After(5 * time.Second):
			return fmt.Errorf("[%s] timed out waiting for result, got %d so far", c.name, len(actual))
		}
	}

	if diff := netParseCmp(c.expected, actual); diff != "" {
		return fmt.Errorf("[%s] found diff:\n%s", c.name, diff)
	}
	return nil
}

func TestTCPFlow(t *testing.T) {
	testCases := []tcpFlowTestCase{
		{
			name:   "unparsable single byte",
			inputs: []string{"?"},
			expected: []akinet.ParsedNetworkTraffic{
				dummyPNT(akinet.DroppedBytes(len("?"))),
			},
		},
		{
			name:   "discard single byte from front and back",
			inputs: []string{"?prince|bread!|&"},
			expected: []akinet.ParsedNetworkTraffic{
				dummyPNT(akinet.DroppedBytes(len("?"))),
				dummyPNT(akinet.AkitaPrince("bread!")),
				dummyPNT(akinet.DroppedBytes(len("&"))),
			},
		},
		{
			name:   "discard single byte from front and back - segmented",
			inputs: []string{"?pr", "ince|bre", "ad!|&"},
			expected: []akinet.ParsedNetworkTraffic{
				dummyPNT(akinet.DroppedBytes(len("?"))),
				dummyPNT(akinet.AkitaPrince("bread!")),
				dummyPNT(akinet.DroppedBytes(len("&"))),
			},
		},
		{
			name:   "discard multiple bytes from front and back - segmented",
			inputs: []string{"hellopr", "ince|bre", "ad!", "|bye"},
			expected: []akinet.ParsedNetworkTraffic{
				dummyPNT(akinet.DroppedBytes(len("hello"))),
				dummyPNT(akinet.AkitaPrince("bread!")),
				dummyPNT(akinet.DroppedBytes(len("bye"))),
			},
		},
		{
			name:   "two requests back to back - same packet with empty end packet",
			inputs: []string{"prince|bread!|prince|yay!|", ""},
			expected: []akinet.ParsedNetworkTraffic{
				dummyPNT(akinet.AkitaPrince("bread!")),
				dummyPNT(akinet.AkitaPrince("yay!")),
			},
		},
		{
			name:   "two requests back to back - same packet",
			inputs: []string{"prince|bread!|prince|yay!|"},
			expected: []akinet.ParsedNetworkTraffic{
				dummyPNT(akinet.AkitaPrince("bread!")),
				dummyPNT(akinet.AkitaPrince("yay!")),
			},
		},
		{
			name:   "two requests back to back - segmented",
			inputs: []string{"pr", "ince|bre", "ad!|pr", "ince|yay!|"},
			expected: []akinet.ParsedNetworkTraffic{
				dummyPNT(akinet.AkitaPrince("bread!")),
				dummyPNT(akinet.AkitaPrince("yay!")),
			},
		},
		{
			name:   "second request incomplete",
			inputs: []string{"pr", "ince|bre", "ad!|pr", "ince|ya"},
			expected: []akinet.ParsedNetworkTraffic{
				dummyPNT(akinet.AkitaPrince("bread!")),
				dummyPNT(akinet.DroppedBytes(len("prince|ya"))),
			},
		},
		{
			name:   "empty last packet",
			inputs: []string{"pr", "ince|bre", "ad!|pr", "ince|yay!|", ""},
			expected: []akinet.ParsedNetworkTraffic{
				dummyPNT(akinet.AkitaPrince("bread!")),
				dummyPNT(akinet.AkitaPrince("yay!")),
			},
		},
	}

	for _, c := range testCases {
		if err := runTCPFlowTestCase(c); err != nil {
			t.Error(err)
		}
	}
}

// A lost packet leaves a gap that the assembler waits on, queueing everything
// after it. When the flush finally skips the gap, it hands every queued message
// to the stream in a single ReassembledSG call. All of them must be parsed
// then; otherwise the backlog only drains one message per later packet, and
// this direction falls permanently behind the other one.
func TestTCPFlowFlushAfterGapParsesAllQueuedMessages(t *testing.T) {
	out := make(chan akinet.ParsedNetworkTraffic, 100)
	fs := akinet.TCPParserFactorySelector([]akinet.TCPParserFactory{princeParserFactory{}})
	streamFactory := newTCPStreamFactory(&fakeClock{testTime}, chanSink(out), fs, capturestats.New(), false, nil, nil, "")
	assembler := reassembly.NewAssembler(reassembly.NewStreamPool(streamFactory))

	ts := testTime
	assemble := func(payload string, seq uint32) {
		pkt := CreatePacketWithSeq(ip1, ip2, port1, port2, []byte(payload), seq)
		pkt.Metadata().CaptureInfo.Timestamp = ts
		ts = ts.Add(time.Millisecond)
		tcp := pkt.TransportLayer().(*layers.TCP)
		assembler.AssembleWithContext(pkt.NetworkLayer().NetworkFlow(), tcp, contextFromTCPPacket(pkt, tcp))
	}

	// Each message is a packet of its own, as with keep-alive requests.
	msgs := []string{"prince|one|", "prince|two|", "prince|three|", "prince|four|", "prince|five|"}
	seq := uint32(100)
	for i, m := range msgs {
		// The kernel dropped "two".
		if i != 1 {
			assemble(m, seq)
		}
		seq += uint32(len(m))
	}

	// Skip the gap, as ParseFromInterface's ticker does once the queued data is
	// older than StreamTimeoutSeconds.
	assembler.FlushWithOptions(reassembly.FlushOptions{T: ts.Add(time.Second)})

	var got []akinet.AkitaPrince
	for len(out) > 0 {
		if p, ok := (<-out).Content.(akinet.AkitaPrince); ok {
			got = append(got, p)
		}
	}
	expected := []akinet.AkitaPrince{"one", "three", "four", "five"}
	if diff := netParseCmp(expected, got); diff != "" {
		t.Errorf("messages parsed by the time the gap was flushed:\n%s", diff)
	}
}

func TestTCPFlowReportsDiscardedResponse(t *testing.T) {
	pool, err := buffer_pool.MakeBufferPool(1024*1024, 4*1024)
	if err != nil {
		t.Fatalf("creating buffer pool: %v", err)
	}

	stats := capturestats.New()
	var reported string
	out := make(chan akinet.ParsedNetworkTraffic, 10)
	fs := akinet.TCPParserFactorySelector([]akinet.TCPParserFactory{
		akihttp.NewHTTPResponseParserFactory(pool),
	})
	f := newTestTCPFlow(out, fs, stats, func(event string, _ uint64) {
		reported = event
	})
	sg := &fakeScatterGather{
		data:       memview.New([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")),
		isEnd:      true,
		nilContext: true,
	}

	f.reassembled(sg, nil)

	if got := stats.Snapshot().DiscardedResponses; got != 1 {
		t.Fatalf("expected one discarded response, got %d", got)
	}
	if reported != "pcap_parser_discarded_response" {
		t.Fatalf("expected parser discard telemetry, got %q", reported)
	}
}

func TestTCPFlowReportsDiscardedRequest(t *testing.T) {
	pool, err := buffer_pool.MakeBufferPool(1024*1024, 4*1024)
	if err != nil {
		t.Fatalf("creating buffer pool: %v", err)
	}

	stats := capturestats.New()
	var reported string
	out := make(chan akinet.ParsedNetworkTraffic, 10)
	fs := akinet.TCPParserFactorySelector([]akinet.TCPParserFactory{
		akihttp.NewHTTPRequestParserFactory(pool),
	})
	f := newTestTCPFlow(out, fs, stats, func(event string, _ uint64) {
		reported = event
	})
	sg := &fakeScatterGather{
		data:       memview.New([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")),
		isEnd:      true,
		nilContext: true,
	}

	f.reassembled(sg, nil)

	if got := stats.Snapshot().DiscardedRequests; got != 1 {
		t.Fatalf("expected one discarded request, got %d", got)
	}
	if reported != "pcap_parser_discarded_request" {
		t.Fatalf("expected parser discard telemetry, got %q", reported)
	}
}

// newPooledResponse returns an HTTP response whose body holds every chunk of a
// fresh two-chunk pool, along with the pool and its full size in bytes.
func newPooledResponse(t *testing.T) (akinet.HTTPResponse, buffer_pool.BufferPool, int) {
	t.Helper()

	const chunkSize = 16
	const poolSize = 2 * chunkSize
	pool, err := buffer_pool.MakeBufferPool(poolSize, chunkSize)
	if err != nil {
		t.Fatal(err)
	}

	body := pool.NewBuffer()
	if _, err := body.Write(make([]byte, poolSize)); err != nil {
		t.Fatalf("filling body: %v", err)
	}
	resp := akinet.FromStdResponse(uuid.New(), 0, &http.Response{StatusCode: 200, Header: http.Header{}}, body)
	return resp, pool, poolSize
}

// poolHasRoom reports whether n bytes can still be taken from pool.
func poolHasRoom(pool buffer_pool.BufferPool, n int) bool {
	probe := pool.NewBuffer()
	defer probe.Release()
	_, err := probe.Write(make([]byte, n))
	return err == nil
}

// An event dropped because the channel is full must give its body buffers back
// to the pool, or the pool runs dry and later bodies come out empty.
func TestEnqueueReleasesBuffersOfDroppedEvent(t *testing.T) {
	resp, pool, poolSize := newPooledResponse(t)
	stats := capturestats.New()
	p := &NetworkTrafficParser{
		pntCh: make(chan akinet.ParsedNetworkTraffic), // Nobody reads: always full.
		stats: stats,
	}

	p.Enqueue(dummyPNT(resp))

	if got := stats.Snapshot().PNTDropped; got != 1 {
		t.Fatalf("PNTDropped = %d, want 1", got)
	}
	if !poolHasRoom(pool, poolSize) {
		t.Fatal("dropped event did not return its buffers to the pool")
	}
}

// Every drop lands in exactly one kind, so the kinds always sum to the total.
func TestEnqueueCountsDroppedEventsByKind(t *testing.T) {
	stats := capturestats.New()
	p := &NetworkTrafficParser{
		pntCh: make(chan akinet.ParsedNetworkTraffic), // Nobody reads: always full.
		stats: stats,
	}

	// Zero-value HTTP messages have no buffer to release, so build real ones.
	pool, err := buffer_pool.MakeBufferPool(64, 16)
	if err != nil {
		t.Fatal(err)
	}
	newReq := func() akinet.HTTPRequest {
		return akinet.FromStdRequest(uuid.New(), 0,
			&http.Request{Method: "GET", URL: &url.URL{Path: "/"}, Header: http.Header{}},
			pool.NewBuffer())
	}
	resp, _, _ := newPooledResponse(t)

	for _, c := range []akinet.ParsedNetworkContent{
		newReq(),
		newReq(),
		resp,
		akinet.TCPPacketMetadata{},
		akinet.TCPPacketMetadata{},
		akinet.TCPPacketMetadata{},
		akinet.TCPConnectionMetadata{},
		akinet.DroppedBytes(10),
		akinet.TLSClientHello{},
		akinet.HTTP2ConnectionPreface{},
	} {
		p.Enqueue(dummyPNT(c))
	}

	snap := stats.Snapshot()
	want := map[capturestats.PNTKind]uint64{
		capturestats.PNTKindHTTPRequest:           2,
		capturestats.PNTKindHTTPResponse:          1,
		capturestats.PNTKindTCPPacketMetadata:     3,
		capturestats.PNTKindTCPConnectionMetadata: 1,
		capturestats.PNTKindUnparsedBytes:         1,
		capturestats.PNTKindTLSHandshake:          1,
		capturestats.PNTKindOther:                 1,
	}
	var sum uint64
	for k := capturestats.PNTKind(0); k < capturestats.PNTKindCount; k++ {
		if got := snap.PNTDroppedByKind[k]; got != want[k] {
			t.Errorf("kind %s = %d, want %d", k.Name(), got, want[k])
		}
		sum += snap.PNTDroppedByKind[k]
	}
	if sum != snap.PNTDropped || snap.PNTDropped != 10 {
		t.Fatalf("kinds sum to %d, PNTDropped = %d, want both 10", sum, snap.PNTDropped)
	}
}

// A delivered event keeps its buffers: the consumer releases them after use.
func TestEnqueueKeepsBuffersOfDeliveredEvent(t *testing.T) {
	resp, pool, _ := newPooledResponse(t)
	stats := capturestats.New()
	out := make(chan akinet.ParsedNetworkTraffic, 1)
	p := &NetworkTrafficParser{pntCh: out, stats: stats}

	p.Enqueue(dummyPNT(resp))

	if got := stats.Snapshot().PNTDropped; got != 0 {
		t.Fatalf("PNTDropped = %d, want 0", got)
	}
	if poolHasRoom(pool, 1) {
		t.Fatal("delivered event's buffers were released before the consumer saw it")
	}
	delivered := <-out
	if delivered.Content.(akinet.HTTPResponse).Body.Len() == 0 {
		t.Fatal("delivered event lost its body")
	}
}
