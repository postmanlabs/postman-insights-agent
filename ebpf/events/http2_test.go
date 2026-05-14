// SPDX-License-Identifier: Apache-2.0

package events

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
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
	s := newH2State("test")
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
	s := newH2State("test")
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
	s := newH2State("test")
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
	s := newH2State("test")
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
	s := newH2State("test")
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
	s := newH2State("test")
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
