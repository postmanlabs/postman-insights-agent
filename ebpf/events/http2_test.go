// SPDX-License-Identifier: Apache-2.0

package events

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/google/uuid"
	"golang.org/x/net/http2/hpack"
)

// buildHeadersFrame constructs an HTTP/2 HEADERS frame with END_HEADERS and
// optionally END_STREAM set.
func buildHeadersFrame(t *testing.T, streamID uint32, endStream bool, fields []hpack.HeaderField) []byte {
	t.Helper()
	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	for _, f := range fields {
		if err := enc.WriteField(f); err != nil {
			t.Fatalf("hpack encode: %v", err)
		}
	}
	payload := hbuf.Bytes()
	frame := make([]byte, 9+len(payload))
	// length (24 bits)
	frame[0] = byte(len(payload) >> 16)
	frame[1] = byte(len(payload) >> 8)
	frame[2] = byte(len(payload))
	frame[3] = h2FrameHeaders
	var flags uint8 = h2FlagEndHeaders
	if endStream {
		flags |= h2FlagEndStream
	}
	frame[4] = flags
	// stream ID (31 bits, R bit = 0)
	frame[5] = byte(streamID >> 24)
	frame[6] = byte(streamID >> 16)
	frame[7] = byte(streamID >> 8)
	frame[8] = byte(streamID)
	copy(frame[9:], payload)
	return frame
}

func buildDataFrame(streamID uint32, endStream bool, body []byte) []byte {
	frame := make([]byte, 9+len(body))
	frame[0] = byte(len(body) >> 16)
	frame[1] = byte(len(body) >> 8)
	frame[2] = byte(len(body))
	frame[3] = h2FrameData
	if endStream {
		frame[4] = h2FlagEndStream
	}
	frame[5] = byte(streamID >> 24)
	frame[6] = byte(streamID >> 16)
	frame[7] = byte(streamID >> 8)
	frame[8] = byte(streamID)
	copy(frame[9:], body)
	return frame
}

// TestH2_RequestNoBody — HEADERS with END_STREAM emits an HTTPRequest.
func TestH2_RequestNoBody(t *testing.T) {
	s := newH2State(akinet.TCPBidiID(uuid.New()))
	frame := buildHeadersFrame(t, 1, true, []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/users/42"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "api.example.com"},
		{Name: "accept", Value: "application/json"},
	})
	out := s.feed(frame, time.Now(), "iface-1")
	if len(out) != 1 {
		t.Fatalf("expected 1 PNT, got %d", len(out))
	}
	req, ok := out[0].Content.(akinet.HTTPRequest)
	if !ok {
		t.Fatalf("expected HTTPRequest, got %T", out[0].Content)
	}
	if req.Method != "GET" {
		t.Errorf("Method = %q, want GET", req.Method)
	}
	if req.URL.Path != "/users/42" {
		t.Errorf("Path = %q, want /users/42", req.URL.Path)
	}
	if req.Host != "api.example.com" {
		t.Errorf("Host = %q, want api.example.com", req.Host)
	}
	if got := req.Header.Get("accept"); got != "application/json" {
		t.Errorf("accept = %q, want application/json", got)
	}
}

// TestH2_RequestWithBody — HEADERS + DATA(END_STREAM) → HTTPRequest with body.
func TestH2_RequestWithBody(t *testing.T) {
	s := newH2State(akinet.TCPBidiID(uuid.New()))
	headers := buildHeadersFrame(t, 3, false, []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: "/echo"},
		{Name: ":authority", Value: "h2.local"},
	})
	body := buildDataFrame(3, true, []byte(`{"hello":"world"}`))

	all := append(headers, body...)
	out := s.feed(all, time.Now(), "iface-1")
	if len(out) != 1 {
		t.Fatalf("expected 1 PNT, got %d", len(out))
	}
	req := out[0].Content.(akinet.HTTPRequest)
	if req.Method != "POST" {
		t.Errorf("Method = %q", req.Method)
	}
	if req.Body.String() != `{"hello":"world"}` {
		t.Errorf("Body = %q", req.Body.String())
	}
}

// TestH2_Response — :status pseudo-header yields an HTTPResponse.
func TestH2_Response(t *testing.T) {
	s := newH2State(akinet.TCPBidiID(uuid.New()))
	frame := buildHeadersFrame(t, 1, true, []hpack.HeaderField{
		{Name: ":status", Value: "204"},
		{Name: "content-length", Value: "0"},
	})
	out := s.feed(frame, time.Now(), "iface-1")
	if len(out) != 1 {
		t.Fatalf("expected 1 PNT, got %d", len(out))
	}
	resp, ok := out[0].Content.(akinet.HTTPResponse)
	if !ok {
		t.Fatalf("expected HTTPResponse, got %T", out[0].Content)
	}
	if resp.StatusCode != 204 {
		t.Errorf("StatusCode = %d, want 204", resp.StatusCode)
	}
}

// TestH2_Preface — preface is stripped before frame parsing.
func TestH2_Preface(t *testing.T) {
	s := newH2State(akinet.TCPBidiID(uuid.New()))
	frame := buildHeadersFrame(t, 1, true, []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/"},
	})
	all := append([]byte(H2Preface), frame...)
	out := s.feed(all, time.Now(), "iface-1")
	if len(out) != 1 {
		t.Fatalf("expected 1 PNT after preface, got %d", len(out))
	}
}

// TestH2_MultipleStreams — interleaved frames on two streams produce two PNTs.
func TestH2_MultipleStreams(t *testing.T) {
	s := newH2State(akinet.TCPBidiID(uuid.New()))
	h1 := buildHeadersFrame(t, 1, false, []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/a"},
	})
	h3 := buildHeadersFrame(t, 3, false, []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/b"},
	})
	d1 := buildDataFrame(1, true, []byte("first"))
	d3 := buildDataFrame(3, true, []byte("second"))

	// Interleave.
	all := append(h1, h3...)
	all = append(all, d3...)
	all = append(all, d1...)
	out := s.feed(all, time.Now(), "iface-1")
	if len(out) != 2 {
		t.Fatalf("expected 2 PNTs, got %d", len(out))
	}
	paths := map[string]string{}
	for _, p := range out {
		r := p.Content.(akinet.HTTPRequest)
		paths[r.URL.Path] = r.Body.String()
	}
	if paths["/a"] != "first" {
		t.Errorf("stream 1 body = %q, want first", paths["/a"])
	}
	if paths["/b"] != "second" {
		t.Errorf("stream 3 body = %q, want second", paths["/b"])
	}
}

// TestH2_ChunkedDelivery — bytes split across multiple feed calls reassemble.
func TestH2_ChunkedDelivery(t *testing.T) {
	s := newH2State(akinet.TCPBidiID(uuid.New()))
	frame := buildHeadersFrame(t, 1, true, []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/chunked"},
	})
	var got []akinet.ParsedNetworkTraffic
	// Feed one byte at a time.
	for i := 0; i < len(frame); i++ {
		got = append(got, s.feed(frame[i:i+1], time.Now(), "iface-1")...)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 PNT, got %d", len(got))
	}
	if got[0].Content.(akinet.HTTPRequest).URL.Path != "/chunked" {
		t.Errorf("Path = %q", got[0].Content.(akinet.HTTPRequest).URL.Path)
	}
}

// TestIsHTTP2Preface covers both detection paths.
func TestIsHTTP2Preface(t *testing.T) {
	if !IsHTTP2Preface([]byte(H2Preface)) {
		t.Error("preface bytes should detect as h2")
	}
	settings := []byte{0, 0, 0, h2FrameSettings, 0, 0, 0, 0, 0}
	if !IsHTTP2Preface(settings) {
		t.Error("zero-length SETTINGS frame should detect as h2")
	}
	if IsHTTP2Preface([]byte("GET / HTTP/1.1\r\n")) {
		t.Error("HTTP/1.1 should NOT detect as h2")
	}
}

// Ensure http import isn't pruned.
var _ = http.Header{}

// TestIsHTTP2Frame: mid-stream detection accepts plausible frame headers,
// rejects all-zero garbage (DATA frame on stream 0 is illegal), and rejects
// HTTP/1.1 plaintext.
func TestIsHTTP2Frame(t *testing.T) {
	// A HEADERS frame on stream 1 — a typical first-frame-after-attach.
	hdr := buildHeadersFrame(t, 1, true, []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: "/svc.Foo/Bar"},
	})
	if !IsHTTP2Frame(hdr) {
		t.Error("HEADERS frame should detect as h2")
	}

	// All-zero — type=0 (DATA), stream_id=0 — illegal per RFC 7540 §6.1.
	zeros := make([]byte, 64)
	if IsHTTP2Frame(zeros) {
		t.Error("all-zero garbage must not detect as h2 (DATA on stream 0 is illegal)")
	}

	// HTTP/1.1 ASCII shouldn't be confused with an h2 frame header.
	if IsHTTP2Frame([]byte("GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")) {
		t.Error("HTTP/1.1 request must not detect as h2 frame")
	}

	// SETTINGS on stream != 0 is illegal — must reject.
	badSettings := []byte{0, 0, 0, h2FrameSettings, 0, 0, 0, 0, 1}
	if IsHTTP2Frame(badSettings) {
		t.Error("SETTINGS frame on non-zero stream must not detect")
	}
}

// TestH2_AuthorityFromHostHeader — when :authority is omitted but a plain
// Host header is present (common for gRPC over HTTP/2), the emitted URL must
// not be "https:///path".
func TestH2_AuthorityFromHostHeader(t *testing.T) {
	s := newH2State(akinet.TCPBidiID(uuid.New()))
	frame := buildHeadersFrame(t, 5, true, []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: "/phase5c2.Greeter/SayHello"},
		{Name: ":scheme", Value: "https"},
		{Name: "host", Value: "localhost:8446"},
		{Name: "content-type", Value: "application/grpc+proto"},
	})
	out := s.feed(frame, time.Now(), "iface-1")
	if len(out) != 1 {
		t.Fatalf("expected 1 PNT, got %d", len(out))
	}
	req := out[0].Content.(akinet.HTTPRequest)
	if req.URL.Host != "localhost:8446" {
		t.Errorf("URL.Host = %q, want localhost:8446", req.URL.Host)
	}
	if got := req.URL.String(); got != "https://localhost:8446/phase5c2.Greeter/SayHello" {
		t.Errorf("URL = %q, want https://localhost:8446/phase5c2.Greeter/SayHello", got)
	}
}

// TestH2_GRPCFraming: a gRPC stream (content-type: application/grpc) with
// a length-prefixed message inside DATA should be decoded and the message
// body should equal the protobuf payload (framing stripped).
func TestH2_GRPCFraming(t *testing.T) {
	s := newH2State(akinet.TCPBidiID(uuid.New()))

	// Build a gRPC request: HEADERS with :method=POST, :path=/svc/Method,
	// content-type: application/grpc, followed by a DATA frame whose
	// payload is [0 (uncompressed)][4-byte BE length][payload bytes].
	headers := buildHeadersFrame(t, 1, false, []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: "/demo.MyService/Check"},
		{Name: ":authority", Value: "localhost"},
		{Name: ":scheme", Value: "https"},
		{Name: "content-type", Value: "application/grpc+proto"},
	})

	payload := []byte("hello-proto-bytes")
	framed := append([]byte{0, 0, 0, 0, byte(len(payload))}, payload...)
	data := buildDataFrame(1, true, framed)

	got := s.feed(append(headers, data...), time.Now(), "iface-1")
	if len(got) != 1 {
		t.Fatalf("expected 1 PNT, got %d", len(got))
	}
	req, ok := got[0].Content.(akinet.HTTPRequest)
	if !ok {
		t.Fatalf("expected HTTPRequest, got %T", got[0].Content)
	}
	if req.URL.Path != "/demo.MyService/Check" {
		t.Errorf("Path = %q", req.URL.Path)
	}
	if req.Body.String() != string(payload) {
		t.Errorf("Body = %q, want %q (framing should be stripped)", req.Body.String(), payload)
	}
	if req.Header.Get("X-Pi-Grpc-Messages") != "1" {
		t.Errorf("X-Pi-Grpc-Messages = %q, want \"1\"", req.Header.Get("X-Pi-Grpc-Messages"))
	}
	if req.Header.Get("X-Pi-Grpc-Total-Bytes") != "17" {
		t.Errorf("X-Pi-Grpc-Total-Bytes = %q, want \"17\"", req.Header.Get("X-Pi-Grpc-Total-Bytes"))
	}
}

// TestH2_GRPCFramingSplit: a gRPC message that arrives split across two
// DATA frames must be reassembled (framing reassembly).
func TestH2_GRPCFramingSplit(t *testing.T) {
	s := newH2State(akinet.TCPBidiID(uuid.New()))

	headers := buildHeadersFrame(t, 3, false, []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: "/svc/Foo"},
		{Name: "content-type", Value: "application/grpc"},
	})
	payload := bytes.Repeat([]byte{'x'}, 100)
	framed := append([]byte{0, 0, 0, 0, byte(len(payload))}, payload...)

	// Split the framed bytes mid-payload across two DATA frames.
	part1 := buildDataFrame(3, false, framed[:30])
	part2 := buildDataFrame(3, true, framed[30:])

	got := s.feed(headers, time.Now(), "iface-1")
	got = append(got, s.feed(part1, time.Now(), "iface-1")...)
	got = append(got, s.feed(part2, time.Now(), "iface-1")...)
	if len(got) != 1 {
		t.Fatalf("expected 1 PNT, got %d", len(got))
	}
	req := got[0].Content.(akinet.HTTPRequest)
	if req.Body.String() != string(payload) {
		t.Errorf("reassembled body len=%d, want %d", req.Body.Len(), len(payload))
	}
}
