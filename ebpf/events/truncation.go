// SPDX-License-Identifier: Apache-2.0

package events

import (
	"net/http"
	"strconv"

	"github.com/akitasoftware/akita-libs/akinet"
)

// Synthetic HTTP headers injected onto parsed messages when the underlying
// BPF events reported truncation. These names are agent-private — they
// never exist on the wire, and they survive the redactor unchanged because
// the values are not sensitive.
//
// Convention (design doc §7.3 gap #2):
//
//   X-Postman-Insights-Body-Truncated: true
//   X-Postman-Insights-Body-Dropped-Bytes: <int>
//
// Why "Dropped-Bytes" rather than "Original-Length":
//
//   The BPF layer caps each *event*, not each *message*. A single HTTP
//   message can be carried by N events; some may be truncated, others not.
//   We can honestly report the sum of bytes the BPF cap dropped across
//   contributing events, but we cannot reconstruct the full body length
//   without unbounded buffering — exactly what the cap exists to prevent.
//   Reporting "dropped bytes" is provably correct; reporting "original
//   length" would require the redactor / backend to do arithmetic on a
//   value that doesn't always equal what they think it does.
const (
	HeaderBodyTruncated    = "X-Postman-Insights-Body-Truncated"
	HeaderBodyDroppedBytes = "X-Postman-Insights-Body-Dropped-Bytes"
)

// annotateTruncation injects the synthetic body-truncation headers onto a
// parsed network content if it is an HTTP request or response.
//
// Other content types (e.g. when we eventually emit raw / opaque records)
// are returned unchanged. We deliberately do NOT panic on unknown content;
// the adapter must remain forward-compatible with new parser outputs.
func annotateTruncation(c akinet.ParsedNetworkContent, droppedBytes uint64) {
	switch v := c.(type) {
	case akinet.HTTPRequest:
		setTruncationHeaders(v.Header, droppedBytes)
	case akinet.HTTPResponse:
		setTruncationHeaders(v.Header, droppedBytes)
	case *akinet.HTTPRequest:
		setTruncationHeaders(v.Header, droppedBytes)
	case *akinet.HTTPResponse:
		setTruncationHeaders(v.Header, droppedBytes)
	}
}

// setTruncationHeaders writes the two synthetic headers into a parsed HTTP
// message. The Header field is an http.Header (a map type); if it happens
// to be nil (parser bug), we no-op rather than panic.
func setTruncationHeaders(h http.Header, droppedBytes uint64) {
	if h == nil {
		return
	}
	h.Set(HeaderBodyTruncated, "true")
	h.Set(HeaderBodyDroppedBytes, strconv.FormatUint(droppedBytes, 10))
}
