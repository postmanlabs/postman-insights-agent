package pcap

import (
	"fmt"
	"net"
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
	f := newTCPFlow(&fakeClock{testTime}, dummyBidiID, dummyNetFlow, dummyTCPPacketFlow, out, fs, capturestats.New(), nil, nil)

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
	f := newTCPFlow(&fakeClock{testTime}, dummyBidiID, dummyNetFlow, dummyTCPPacketFlow, out, fs, stats, nil, func(event string) {
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
	if reported != "parser_discarded_response" {
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
	f := newTCPFlow(&fakeClock{testTime}, dummyBidiID, dummyNetFlow, dummyTCPPacketFlow, out, fs, stats, nil, func(event string) {
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
	if reported != "parser_discarded_request" {
		t.Fatalf("expected parser discard telemetry, got %q", reported)
	}
}
