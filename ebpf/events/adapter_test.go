// SPDX-License-Identifier: Apache-2.0

package events

import (
	"testing"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	akihttp "github.com/akitasoftware/akita-libs/akinet/http"
	"github.com/akitasoftware/akita-libs/buffer_pool"
)

// feed copies `data` into a single SSLEvent and pushes it through Feed.
// Splits at MaxEventPayload boundaries to mirror what the BPF side does.
func feed(t *testing.T, a *Adapter, pid uint32, ssl uint64, dir uint8, data []byte) {
	t.Helper()
	mono := time.Unix(0, 0)
	for off := 0; off < len(data); off += MaxEventPayload {
		end := off + MaxEventPayload
		if end > len(data) {
			end = len(data)
		}
		ev := &SSLEvent{
			PID:         pid,
			TID:         pid,
			SSLCtx:      ssl,
			Direction:   dir,
			LenCaptured: uint32(end - off),
			LenTotal:    uint32(end - off),
			TimestampNS: uint64(off), // monotonically increasing
		}
		copy(ev.Payload[:], data[off:end])
		a.Feed(ev, mono)
	}
}

func newTestAdapter(t *testing.T) (*Adapter, chan akinet.ParsedNetworkTraffic) {
	t.Helper()
	pool, err := buffer_pool.MakeBufferPool(64*1024*1024, 4096)
	if err != nil {
		t.Fatalf("buffer pool: %v", err)
	}
	fs := akinet.TCPParserFactorySelector{
		akihttp.NewHTTPRequestParserFactory(pool),
		akihttp.NewHTTPResponseParserFactory(pool),
	}
	out := make(chan akinet.ParsedNetworkTraffic, 32)
	return NewAdapter(fs, out), out
}

// One complete HTTP/1.1 request in a single eBPF event yields one HTTPRequest.
func TestAdapter_SimpleRequest(t *testing.T) {
	a, out := newTestAdapter(t)
	req := []byte("GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n")

	feed(t, a, 100, 0xAAAA, DirEgress, req)

	select {
	case pnt := <-out:
		r, ok := pnt.Content.(akinet.HTTPRequest)
		if !ok {
			t.Fatalf("expected HTTPRequest, got %T", pnt.Content)
		}
		if r.Method != "GET" {
			t.Errorf("Method = %q, want GET", r.Method)
		}
		if r.URL == nil || r.URL.Path != "/hello" {
			t.Errorf("URL path = %v, want /hello", r.URL)
		}
		if pnt.Interface != "ebpf-pid-100" {
			t.Errorf("Interface = %q, want ebpf-pid-100", pnt.Interface)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HTTPRequest")
	}
}

// A complete HTTP/1.1 response with body yields one HTTPResponse.
func TestAdapter_SimpleResponse(t *testing.T) {
	a, out := newTestAdapter(t)
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")

	feed(t, a, 200, 0xBBBB, DirIngress, resp)

	select {
	case pnt := <-out:
		r, ok := pnt.Content.(akinet.HTTPResponse)
		if !ok {
			t.Fatalf("expected HTTPResponse, got %T", pnt.Content)
		}
		if r.StatusCode != 200 {
			t.Errorf("StatusCode = %d, want 200", r.StatusCode)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HTTPResponse")
	}
}

// HTTP keep-alive: two requests on one flow → two HTTPRequest emissions.
func TestAdapter_PipelinedRequests(t *testing.T) {
	a, out := newTestAdapter(t)
	pipeline := []byte(
		"GET /a HTTP/1.1\r\nHost: x\r\n\r\n" +
			"POST /b HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nfoo")

	feed(t, a, 300, 0xCCCC, DirEgress, pipeline)

	var got []akinet.HTTPRequest
	deadline := time.After(2 * time.Second)
loop:
	for {
		select {
		case pnt := <-out:
			if r, ok := pnt.Content.(akinet.HTTPRequest); ok {
				got = append(got, r)
				if len(got) == 2 {
					break loop
				}
			}
		case <-deadline:
			break loop
		}
	}
	if len(got) != 2 {
		t.Fatalf("got %d requests, want 2", len(got))
	}
	if got[0].Method != "GET" || got[0].URL.Path != "/a" {
		t.Errorf("first: %s %s", got[0].Method, got[0].URL)
	}
	if got[1].Method != "POST" || got[1].URL.Path != "/b" {
		t.Errorf("second: %s %s", got[1].Method, got[1].URL)
	}
	if got[0].Seq == got[1].Seq {
		t.Errorf("pipelined requests should have distinct pair indices, both Seq=%d", got[0].Seq)
	}
}

// Ingress request + egress response on the same TLS connection share StreamID
// and Seq so BackendCollector can pair them (mirrors pcap tcpStream.bidiID).
func TestAdapter_RequestResponsePairing(t *testing.T) {
	a, out := newTestAdapter(t)
	const pid uint32 = 52837
	const sslCtx uint64 = 0xDEADBEEF

	req := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

	feed(t, a, pid, sslCtx, DirIngress, req)
	feed(t, a, pid, sslCtx, DirEgress, resp)

	var reqContent akinet.HTTPRequest
	var respContent akinet.HTTPResponse
	for i := 0; i < 2; i++ {
		pnt := <-out
		switch c := pnt.Content.(type) {
		case akinet.HTTPRequest:
			reqContent = c
		case akinet.HTTPResponse:
			respContent = c
		}
	}

	if reqContent.StreamID != respContent.StreamID {
		t.Fatalf("StreamID mismatch: req=%v resp=%v", reqContent.StreamID, respContent.StreamID)
	}
	if reqContent.Seq != respContent.Seq {
		t.Fatalf("Seq mismatch: req=%d resp=%d", reqContent.Seq, respContent.Seq)
	}
}

// Repeated GET / on keep-alive must not reuse the same pair index.
func TestAdapter_KeepAliveDistinctPairKeys(t *testing.T) {
	a, out := newTestAdapter(t)
	const pid uint32 = 52837
	const sslCtx uint64 = 0xDEADBEEF

	req := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	feed(t, a, pid, sslCtx, DirIngress, req)
	first := (<-out).Content.(akinet.HTTPRequest)

	feed(t, a, pid, sslCtx, DirIngress, req)
	second := (<-out).Content.(akinet.HTTPRequest)

	if first.StreamID != second.StreamID {
		t.Fatalf("keep-alive requests should share StreamID")
	}
	if first.Seq == second.Seq {
		t.Fatalf("keep-alive requests must not collide on Seq: both %d", first.Seq)
	}
}

// GET requests with query strings must preserve RawQuery through the adapter.
func TestAdapter_RequestWithQueryParams(t *testing.T) {
	a, out := newTestAdapter(t)
	cases := []struct {
		name     string
		reqLine  string
		wantPath string
		wantRaw  string
	}{
		{
			name:     "single param",
			reqLine:  "GET /phase5b2?q=hello HTTP/1.1\r\nHost: svc:8443\r\n\r\n",
			wantPath: "/phase5b2",
			wantRaw:  "q=hello",
		},
		{
			name:     "multiple params",
			reqLine:  "GET /phase5b2?foo=bar&baz=1 HTTP/1.1\r\nHost: svc:8443\r\n\r\n",
			wantPath: "/phase5b2",
			wantRaw:  "foo=bar&baz=1",
		},
		{
			name:     "encoded",
			reqLine:  "GET /phase5b2?name=John%20Doe&filter=a%26b HTTP/1.1\r\nHost: svc:8443\r\n\r\n",
			wantPath: "/phase5b2",
			wantRaw:  "name=John%20Doe&filter=a%26b",
		},
		{
			name:     "empty value",
			reqLine:  "GET /phase5b2?key=&other=x HTTP/1.1\r\nHost: svc:8443\r\n\r\n",
			wantPath: "/phase5b2",
			wantRaw:  "key=&other=x",
		},
		{
			name:     "repeated keys",
			reqLine:  "GET /phase5b2?tag=a&tag=b HTTP/1.1\r\nHost: svc:8443\r\n\r\n",
			wantPath: "/phase5b2",
			wantRaw:  "tag=a&tag=b",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			feed(t, a, 800, 0x8000+uint64(len(tc.name)), DirEgress, []byte(tc.reqLine))

			select {
			case pnt := <-out:
				r, ok := pnt.Content.(akinet.HTTPRequest)
				if !ok {
					t.Fatalf("expected HTTPRequest, got %T", pnt.Content)
				}
				if r.Method != "GET" {
					t.Errorf("Method = %q, want GET", r.Method)
				}
				if r.URL == nil {
					t.Fatal("URL is nil")
				}
				if r.URL.Path != tc.wantPath {
					t.Errorf("Path = %q, want %q", r.URL.Path, tc.wantPath)
				}
				if r.URL.RawQuery != tc.wantRaw {
					t.Errorf("RawQuery = %q, want %q", r.URL.RawQuery, tc.wantRaw)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for HTTPRequest")
			}
		})
	}
}

// A single request split across multiple eBPF events (one byte per event)
// is still parsed correctly. This simulates the worst case of TLS records
// arriving as many small SSL_read return values.
func TestAdapter_ChunkedDelivery(t *testing.T) {
	a, out := newTestAdapter(t)
	req := []byte("GET /chunk HTTP/1.1\r\nHost: x\r\n\r\n")

	mono := time.Unix(0, 0)
	for i, b := range req {
		ev := &SSLEvent{
			PID: 400, TID: 400, SSLCtx: 0xDDDD, Direction: DirEgress,
			LenCaptured: 1, LenTotal: 1, TimestampNS: uint64(i),
		}
		ev.Payload[0] = b
		a.Feed(ev, mono)
	}

	select {
	case pnt := <-out:
		r, ok := pnt.Content.(akinet.HTTPRequest)
		if !ok {
			t.Fatalf("expected HTTPRequest, got %T", pnt.Content)
		}
		if r.URL.Path != "/chunk" {
			t.Errorf("URL = %v", r.URL)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
}

// Garbage bytes that no factory will ever accept must drop the flow rather
// than buffering forever.
func TestAdapter_GarbageDropsFlow(t *testing.T) {
	a, out := newTestAdapter(t)
	garbage := make([]byte, MaxPendingPerFlow+1024)
	for i := range garbage {
		garbage[i] = '\x00'
	}

	feed(t, a, 500, 0xEEEE, DirEgress, garbage)

	if a.FlowsDropped == 0 {
		t.Errorf("expected FlowsDropped > 0, got 0")
	}
	select {
	case pnt := <-out:
		t.Errorf("unexpected emission: %+v", pnt)
	default:
	}
}

// Two distinct (pid, ssl_ctx) flows are tracked independently.
func TestAdapter_DistinctFlows(t *testing.T) {
	a, out := newTestAdapter(t)
	req1 := []byte("GET /one HTTP/1.1\r\nHost: x\r\n\r\n")
	req2 := []byte("GET /two HTTP/1.1\r\nHost: x\r\n\r\n")

	// Interleave bytes from two flows.
	feed(t, a, 600, 0xF001, DirEgress, req1[:10])
	feed(t, a, 700, 0xF002, DirEgress, req2[:10])
	feed(t, a, 600, 0xF001, DirEgress, req1[10:])
	feed(t, a, 700, 0xF002, DirEgress, req2[10:])

	paths := map[string]bool{}
	deadline := time.After(2 * time.Second)
	for len(paths) < 2 {
		select {
		case pnt := <-out:
			if r, ok := pnt.Content.(akinet.HTTPRequest); ok {
				paths[r.URL.Path] = true
			}
		case <-deadline:
			t.Fatalf("only saw %v", paths)
		}
	}
	if !paths["/one"] || !paths["/two"] {
		t.Errorf("expected both /one and /two, got %v", paths)
	}
}

// control sends a control event (KindJava*) through Feed.
func control(a *Adapter, kind uint8, pid uint32, ssl uint64, payload string) {
	ev := &SSLEvent{PID: pid, TID: pid, SSLCtx: ssl, Kind: kind, LenCaptured: uint32(len(payload)), LenTotal: uint32(len(payload))}
	copy(ev.Payload[:], payload)
	a.Feed(ev, time.Unix(0, 0))
}

// A response delimited by the connection's close (no Content-Length) is
// emitted when the Java agent reports the close, and the connection is
// forgotten.
func TestAdapter_JavaCloseCompletesResponse(t *testing.T) {
	a, out := newTestAdapter(t)
	const ssl = 1<<63 | 7
	feed(t, a, 100, ssl, DirIngress, []byte("GET /stream HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	feed(t, a, 100, ssl, DirEgress, []byte("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nall of it"))
	if _, ok := (<-out).Content.(akinet.HTTPRequest); !ok {
		t.Fatal("first message is not the request")
	}
	select {
	case pnt := <-out:
		t.Fatalf("response emitted before the close: %T", pnt.Content)
	default:
	}

	control(a, KindJavaClose, 100, ssl, "")
	select {
	case pnt := <-out:
		resp, ok := pnt.Content.(akinet.HTTPResponse)
		if !ok {
			t.Fatalf("got %T, want HTTPResponse", pnt.Content)
		}
		if resp.StatusCode != 200 {
			t.Errorf("status %d", resp.StatusCode)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the close did not complete the response")
	}
	if n, _ := a.Snapshot(); n != 0 {
		t.Errorf("%d flows left after the close", n)
	}
	if len(a.conns) != 0 {
		t.Errorf("%d connections left after the close", len(a.conns))
	}

	// A close for a connection the adapter does not know is harmless.
	control(a, KindJavaClose, 100, 1<<63|8, "")
}

// HEARTBEATs count Java agents as alive, and capturing when active; an agent
// not heard from for javaAgentAliveFor is no longer counted.
func TestAdapter_JavaHeartbeats(t *testing.T) {
	a, out := newTestAdapter(t)
	control(a, KindJavaHeartbeat, 100, 1<<63, "agent_version=1.0.0\nstate=active\n")
	control(a, KindJavaHeartbeat, 200, 1<<63, "agent_version=1.0.0\nstate=dormant\n")
	control(a, KindJavaHeartbeat, 200, 1<<63, "agent_version=1.0.0\nstate=dormant\n")
	select {
	case pnt := <-out:
		t.Fatalf("a heartbeat produced traffic: %T", pnt.Content)
	default:
	}
	if n, _ := a.Snapshot(); n != 0 {
		t.Errorf("a heartbeat created %d flows", n)
	}
	s := a.Stats()
	if s.JavaAgentsAlive != 2 || s.JavaAgentsCapturing != 1 {
		t.Errorf("alive %d, capturing %d; want 2, 1", s.JavaAgentsAlive, s.JavaAgentsCapturing)
	}

	a.javaAgents[200].lastSeen = time.Now().Add(-javaAgentAliveFor - time.Second)
	s = a.Stats()
	if s.JavaAgentsAlive != 1 || s.JavaAgentsCapturing != 1 {
		t.Errorf("alive %d, capturing %d after one went quiet; want 1, 1", s.JavaAgentsAlive, s.JavaAgentsCapturing)
	}
	a.GC(time.Now(), time.Minute)
	if len(a.javaAgents) != 1 {
		t.Errorf("%d agents kept after GC, want 1", len(a.javaAgents))
	}
}

// Events of a kind the adapter does not know are ignored.
func TestAdapter_UnknownKind(t *testing.T) {
	a, out := newTestAdapter(t)
	control(a, 99, 100, 0xAAAA, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	select {
	case pnt := <-out:
		t.Fatalf("emitted %T", pnt.Content)
	default:
	}
}

// A Java event carries its connection's addresses from the kernel: the
// adapter uses them without a Resolver, for both directions of the
// connection.
func TestAdapter_KernelTuple(t *testing.T) {
	a, out := newTestAdapter(t)
	const ssl = 1<<63 | 9
	tuple := ConnTuple{Family: ConnFamilyInet, LocalPort: 8443, RemotePort: 51234}
	copy(tuple.LocalAddr[:], []byte{10, 0, 0, 5})
	copy(tuple.RemoteAddr[:], []byte{10, 0, 0, 9})
	mono := time.Unix(0, 0)
	for i, m := range []struct {
		dir  uint8
		data string
	}{
		{DirIngress, "GET /tuple HTTP/1.1\r\nHost: example.com\r\n\r\n"},
		{DirEgress, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"},
	} {
		ev := &SSLEvent{PID: 100, TID: 100, SSLCtx: ssl, Direction: m.dir, Tuple: tuple,
			LenCaptured: uint32(len(m.data)), LenTotal: uint32(len(m.data)), TimestampNS: uint64(i)}
		copy(ev.Payload[:], m.data)
		a.Feed(ev, mono)
	}
	req, resp := <-out, <-out
	if req.SrcIP.String() != "10.0.0.9" || req.SrcPort != 51234 || req.DstIP.String() != "10.0.0.5" || req.DstPort != 8443 {
		t.Errorf("request %s:%d -> %s:%d", req.SrcIP, req.SrcPort, req.DstIP, req.DstPort)
	}
	if resp.SrcIP.String() != "10.0.0.5" || resp.SrcPort != 8443 || resp.DstIP.String() != "10.0.0.9" || resp.DstPort != 51234 {
		t.Errorf("response %s:%d -> %s:%d", resp.SrcIP, resp.SrcPort, resp.DstIP, resp.DstPort)
	}
}

// A connection's addresses that first come with its CLOSE (its earlier
// events had none) are those of the response the close completes.
func TestAdapter_KernelTupleOnClose(t *testing.T) {
	a, out := newTestAdapter(t)
	const ssl = 1<<63 | 10
	feed(t, a, 100, ssl, DirIngress, []byte("GET /late HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	feed(t, a, 100, ssl, DirEgress, []byte("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nall of it"))
	if req := <-out; req.SrcIP != nil && !req.SrcIP.IsUnspecified() {
		t.Fatalf("the request has addresses %s:%d before any event carried them", req.SrcIP, req.SrcPort)
	}

	tuple := ConnTuple{Family: ConnFamilyInet, LocalPort: 8443, RemotePort: 51234}
	copy(tuple.LocalAddr[:], []byte{10, 0, 0, 5})
	copy(tuple.RemoteAddr[:], []byte{10, 0, 0, 9})
	a.Feed(&SSLEvent{PID: 100, TID: 100, SSLCtx: ssl, Kind: KindJavaClose, FD: -1, Tuple: tuple}, time.Unix(0, 0))
	select {
	case resp := <-out:
		if resp.SrcIP.String() != "10.0.0.5" || resp.SrcPort != 8443 || resp.DstIP.String() != "10.0.0.9" || resp.DstPort != 51234 {
			t.Errorf("response %s:%d -> %s:%d", resp.SrcIP, resp.SrcPort, resp.DstIP, resp.DstPort)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the close did not complete the response")
	}
}
