// SPDX-License-Identifier: Apache-2.0

package events

import (
	"net/http"
	"testing"

	"github.com/akitasoftware/akita-libs/akinet"
)

// TestAnnotateTruncation_HTTPRequest_ByValue verifies that the function
// mutates the underlying http.Header map even when the akinet.HTTPRequest
// is passed by value. (http.Header is a map type, so the reference
// semantics work even through value copies.)
func TestAnnotateTruncation_HTTPRequest_ByValue(t *testing.T) {
	h := http.Header{}
	req := akinet.HTTPRequest{Header: h}

	annotateTruncation(req, 1234)

	if got := h.Get(HeaderBodyTruncated); got != "true" {
		t.Errorf("Body-Truncated header: got %q want %q", got, "true")
	}
	if got := h.Get(HeaderBodyDroppedBytes); got != "1234" {
		t.Errorf("Body-Dropped-Bytes header: got %q want %q", got, "1234")
	}
}

// TestAnnotateTruncation_HTTPResponse_ByValue mirrors the request case.
func TestAnnotateTruncation_HTTPResponse_ByValue(t *testing.T) {
	h := http.Header{}
	resp := akinet.HTTPResponse{Header: h}

	annotateTruncation(resp, 4096)

	if got := h.Get(HeaderBodyTruncated); got != "true" {
		t.Errorf("Body-Truncated header: got %q", got)
	}
	if got := h.Get(HeaderBodyDroppedBytes); got != "4096" {
		t.Errorf("Body-Dropped-Bytes header: got %q", got)
	}
}

// TestAnnotateTruncation_HTTPRequest_ByPointer guards against future
// parser refactors that emit *HTTPRequest instead of HTTPRequest.
func TestAnnotateTruncation_HTTPRequest_ByPointer(t *testing.T) {
	req := &akinet.HTTPRequest{Header: http.Header{}}

	annotateTruncation(req, 1)

	if req.Header.Get(HeaderBodyTruncated) != "true" {
		t.Error("annotateTruncation did not set header through *HTTPRequest")
	}
}

// TestAnnotateTruncation_UnknownContent must not panic when the content
// type is something other than HTTP request/response (e.g. a future
// "raw bytes" record). This is the forward-compat invariant.
func TestAnnotateTruncation_UnknownContent(t *testing.T) {
	// Use a value that is NOT a *HTTPRequest, HTTPRequest, *HTTPResponse,
	// or HTTPResponse. Choose a non-nil interface value from a different
	// akinet type.
	var c akinet.ParsedNetworkContent = akinet.DroppedBytes(0)

	// Must not panic; must not require unused arg.
	annotateTruncation(c, 99)
}

// TestAnnotateTruncation_NilHeader must not panic when http.Header is nil.
// Parsers should always allocate a non-nil Header, but defending against
// a parser regression is cheaper than debugging a nil-map write.
func TestAnnotateTruncation_NilHeader(t *testing.T) {
	req := akinet.HTTPRequest{Header: nil}
	annotateTruncation(req, 1) // must not panic
}

// TestAnnotateTruncation_LargeDroppedBytes confirms uint64 formatting
// works for values larger than int32. Real-world flows can exceed 2 GiB
// dropped across a long-lived connection.
func TestAnnotateTruncation_LargeDroppedBytes(t *testing.T) {
	h := http.Header{}
	req := akinet.HTTPRequest{Header: h}
	annotateTruncation(req, 1<<33) // 8 GiB

	if got := h.Get(HeaderBodyDroppedBytes); got != "8589934592" {
		t.Errorf("large dropped-bytes formatted as %q, want 8589934592", got)
	}
}
