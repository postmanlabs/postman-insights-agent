// SPDX-License-Identifier: Apache-2.0

package events

import (
	"testing"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
)

// TestAdapter_TruncatedEvent_TagsEmittedRequest is the gap-2 integration
// test. Feed an SSLEvent that reports truncation (LenTotal > LenCaptured),
// and assert that the synthetic body-truncation headers appear on the
// emitted HTTPRequest.
//
// Without this test, gap 2 is only "code in place" — this proves the
// adapter actually wires Truncated()→synthetic header end to end.
func TestAdapter_TruncatedEvent_TagsEmittedRequest(t *testing.T) {
	a, out := newTestAdapter(t)
	req := []byte("GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n")

	// Send the request as one event, but lie to the adapter that the BPF
	// side dropped 5000 bytes (LenTotal = LenCaptured + 5000). The body is
	// empty here; what matters for the test is that ev.Truncated() returns
	// true, which propagates onto the emitted message.
	mono := time.Unix(0, 0)
	ev := &SSLEvent{
		PID:         42,
		TID:         42,
		SSLCtx:      0xCAFE,
		Direction:   DirEgress,
		LenCaptured: uint32(len(req)),
		LenTotal:    uint32(len(req)) + 5000, // ← truncation signal
		TimestampNS: 0,
	}
	copy(ev.Payload[:], req)
	a.Feed(ev, mono)

	select {
	case pnt := <-out:
		r, ok := pnt.Content.(akinet.HTTPRequest)
		if !ok {
			t.Fatalf("expected HTTPRequest, got %T", pnt.Content)
		}
		if got := r.Header.Get(HeaderBodyTruncated); got != "true" {
			t.Errorf("emitted message missing %s header: got %q", HeaderBodyTruncated, got)
		}
		if got := r.Header.Get(HeaderBodyDroppedBytes); got != "5000" {
			t.Errorf("emitted message %s = %q, want 5000", HeaderBodyDroppedBytes, got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HTTPRequest")
	}
}

// TestAdapter_UntruncatedEvent_NoHeaders is the negative complement: when
// no event in the assembled message was truncated, no synthetic headers
// must appear. Otherwise the headers would lie about a clean capture.
func TestAdapter_UntruncatedEvent_NoHeaders(t *testing.T) {
	a, out := newTestAdapter(t)
	req := []byte("GET /clean HTTP/1.1\r\nHost: example.com\r\n\r\n")

	feed(t, a, 100, 0xAAAA, DirEgress, req) // helper sets LenTotal=LenCaptured

	select {
	case pnt := <-out:
		r, ok := pnt.Content.(akinet.HTTPRequest)
		if !ok {
			t.Fatalf("expected HTTPRequest, got %T", pnt.Content)
		}
		if got := r.Header.Get(HeaderBodyTruncated); got != "" {
			t.Errorf("clean flow leaked %s header: %q", HeaderBodyTruncated, got)
		}
		if got := r.Header.Get(HeaderBodyDroppedBytes); got != "" {
			t.Errorf("clean flow leaked %s header: %q", HeaderBodyDroppedBytes, got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HTTPRequest")
	}
}

// TestAdapter_TruncationAccumulatesAcrossEvents — when an HTTP message is
// assembled from multiple events, AND only some of them are truncated, the
// emitted message's "dropped bytes" must equal the SUM of dropped bytes
// across contributing events. This is the property documented in the
// truncation.go header comment.
func TestAdapter_TruncationAccumulatesAcrossEvents(t *testing.T) {
	a, out := newTestAdapter(t)

	mono := time.Unix(0, 0)
	pid := uint32(7)
	ssl := uint64(0xDEAD)

	// Three events assemble one HTTP request. Event 1 truncates by 100 bytes;
	// event 2 is clean; event 3 truncates by 200 bytes. Expected total: 300.
	chunks := [][]byte{
		[]byte("GET /multi HTT"),
		[]byte("P/1.1\r\nHo"),
		[]byte("st: example.com\r\n\r\n"),
	}
	truncs := []uint32{100, 0, 200}

	for i, chunk := range chunks {
		ev := &SSLEvent{
			PID:         pid,
			TID:         pid,
			SSLCtx:      ssl,
			Direction:   DirEgress,
			LenCaptured: uint32(len(chunk)),
			LenTotal:    uint32(len(chunk)) + truncs[i],
			TimestampNS: uint64(i),
		}
		copy(ev.Payload[:], chunk)
		a.Feed(ev, mono)
	}

	select {
	case pnt := <-out:
		r, ok := pnt.Content.(akinet.HTTPRequest)
		if !ok {
			t.Fatalf("expected HTTPRequest, got %T", pnt.Content)
		}
		if got := r.Header.Get(HeaderBodyTruncated); got != "true" {
			t.Errorf("multi-event flow missing %s: got %q", HeaderBodyTruncated, got)
		}
		// 100 + 0 + 200 = 300
		if got := r.Header.Get(HeaderBodyDroppedBytes); got != "300" {
			t.Errorf("multi-event flow %s = %q, want 300", HeaderBodyDroppedBytes, got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HTTPRequest")
	}
}

// TestAdapter_TruncationResetsBetweenMessages — two back-to-back requests
// on a keep-alive connection. The FIRST sees truncation; the SECOND
// must NOT inherit the first's tag. This is the "reset after emit"
// invariant in drain().
func TestAdapter_TruncationResetsBetweenMessages(t *testing.T) {
	a, out := newTestAdapter(t)
	mono := time.Unix(0, 0)
	pid := uint32(11)
	ssl := uint64(0xBEEF)

	// Request 1 — truncated event
	req1 := []byte("GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n")
	ev1 := &SSLEvent{
		PID: pid, TID: pid, SSLCtx: ssl, Direction: DirEgress,
		LenCaptured: uint32(len(req1)),
		LenTotal:    uint32(len(req1)) + 999,
		TimestampNS: 0,
	}
	copy(ev1.Payload[:], req1)
	a.Feed(ev1, mono)

	// Request 2 — clean event on same flow
	req2 := []byte("GET /second HTTP/1.1\r\nHost: example.com\r\n\r\n")
	ev2 := &SSLEvent{
		PID: pid, TID: pid, SSLCtx: ssl, Direction: DirEgress,
		LenCaptured: uint32(len(req2)),
		LenTotal:    uint32(len(req2)),
		TimestampNS: 1,
	}
	copy(ev2.Payload[:], req2)
	a.Feed(ev2, mono)

	// First emitted message: tagged.
	select {
	case pnt := <-out:
		r := pnt.Content.(akinet.HTTPRequest)
		if r.URL.Path != "/first" {
			t.Fatalf("first message URL = %v, want /first", r.URL)
		}
		if r.Header.Get(HeaderBodyTruncated) != "true" {
			t.Error("first message lost truncation tag")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first request")
	}

	// Second emitted message: must be UNTAGGED.
	select {
	case pnt := <-out:
		r := pnt.Content.(akinet.HTTPRequest)
		if r.URL.Path != "/second" {
			t.Fatalf("second message URL = %v, want /second", r.URL)
		}
		if got := r.Header.Get(HeaderBodyTruncated); got != "" {
			t.Errorf("second message INHERITED first's truncation tag: %q", got)
		}
		if got := r.Header.Get(HeaderBodyDroppedBytes); got != "" {
			t.Errorf("second message INHERITED first's dropped-bytes: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for second request")
	}
}
