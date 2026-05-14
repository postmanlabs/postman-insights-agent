// SPDX-License-Identifier: Apache-2.0
//
// Minimum-viable HTTP/2 frame decoder for the eBPF capture path.
//
// Why this is in the adapter rather than akinet
// -----------------------------------------------
// akinet.TCPParser is documented "SINGLE USE — new parser instance per
// message". HTTP/2 multiplexes many streams over one connection and HPACK
// header compression is stateful across the entire connection, so the
// akinet "fresh parser per message" model doesn't fit. We keep the akinet
// pipeline for HTTP/1, but for HTTP/2 we maintain stateful per-flow
// decoders here and emit ParsedNetworkTraffic directly.
//
// Scope (minimum viable, Phase 3):
//   - Preface detection (RFC 7540 §3.5).
//   - Frame header decoding (9-byte frame header per §4.1).
//   - HEADERS + CONTINUATION frame handling with HPACK decoding to recover
//     :method / :path / :authority / :status and user headers.
//   - DATA frame body bytes attached to the request/response that most
//     recently arrived on the same stream.
//   - Stream-level demultiplexing (multiple in-flight streams).
//
// Out of scope (deliberate gaps):
//   - HTTP/2 server push (PUSH_PROMISE).
//   - Priority frames, GOAWAY semantics, WINDOW_UPDATE handling.
//   - Trailer decoding.
//   - Stream-level state machine validation (we accept any sequence the
//     wire shows).
//
// References:
//   RFC 7540 (HTTP/2)
//   RFC 7541 (HPACK)
//   golang.org/x/net/http2/hpack (used for HPACK decoding)

package events

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/memview"
	"github.com/google/uuid"
	"golang.org/x/net/http2/hpack"
)

// H2Preface is the connection preface that every HTTP/2 client sends after
// the TLS handshake (RFC 7540 §3.5).
const H2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// Frame type IDs we care about (RFC 7540 §6).
const (
	h2FrameData         uint8 = 0x0
	h2FrameHeaders      uint8 = 0x1
	h2FramePriority     uint8 = 0x2
	h2FrameRstStream    uint8 = 0x3
	h2FrameSettings     uint8 = 0x4
	h2FramePushPromise  uint8 = 0x5
	h2FramePing         uint8 = 0x6
	h2FrameGoaway       uint8 = 0x7
	h2FrameWindowUpdate uint8 = 0x8
	h2FrameContinuation uint8 = 0x9
)

// HEADERS / CONTINUATION flag bits.
const (
	h2FlagEndStream  uint8 = 0x1
	h2FlagAck        uint8 = 0x1 // SETTINGS, PING
	h2FlagEndHeaders uint8 = 0x4
	h2FlagPadded     uint8 = 0x8
	h2FlagPriority   uint8 = 0x20
)

// h2State is the per-flow (per FlowKey) HTTP/2 decoder state.
type h2State struct {
	mu sync.Mutex

	// `pending` accumulates incoming bytes until we have at least a full
	// frame to parse.
	pending []byte

	// HPACK decoder. State across all HEADERS+CONTINUATION frames on this
	// flow (RFC 7541 §3.2).
	hpack *hpack.Decoder

	// In-progress HEADERS+CONTINUATION sequence: HPACK requires CONTINUATION
	// frames to be feed contiguously to the decoder. We accumulate the
	// header block fragment bytes here until END_HEADERS is set.
	headerBlock     []byte
	headersStreamID uint32
	headersEndStream bool

	// Per-stream state, keyed by stream ID.
	streams map[uint32]*h2Stream

	// Connection-flow identity used for emitted PNTs.
	bidiID akinet.TCPBidiID
}

// h2Stream accumulates pseudo-headers + body for a single HTTP/2 stream.
type h2Stream struct {
	// Pseudo-headers extracted from HEADERS.
	method    string
	path      string
	authority string
	scheme    string
	status    int

	// User headers.
	header http.Header

	// Body bytes accumulated from DATA frames. Capped at h2MaxBodyBytes to
	// bound memory.
	body []byte

	// Whether HEADERS frame indicated END_STREAM (no body coming).
	endStreamOnHeaders bool
}

// h2MaxBodyBytes bounds the body bytes we'll buffer per stream. Mirrors
// adapter's MaxPendingPerFlow.
const h2MaxBodyBytes = 64 * 1024

func newH2State(interfaceTag string) *h2State {
	_ = interfaceTag // reserved
	return &h2State{
		hpack:   hpack.NewDecoder(4096, nil),
		streams: map[uint32]*h2Stream{},
		bidiID:  akinet.TCPBidiID(uuid.New()),
	}
}

// IsHTTP2Preface returns true if the given bytes start with the HTTP/2
// connection preface or look like a SETTINGS frame at stream_id=0 (which is
// what the server sends back as its half of the preface).
func IsHTTP2Preface(b []byte) bool {
	if len(b) >= len(H2Preface) && string(b[:len(H2Preface)]) == H2Preface {
		return true
	}
	// Server-side: starts with SETTINGS frame (type=4, stream_id=0).
	// Frame header is 9 bytes: length(3), type(1), flags(1), R+streamID(4).
	if len(b) >= 9 {
		typ := b[3]
		streamID := binary.BigEndian.Uint32(b[5:9]) & 0x7fffffff
		if typ == h2FrameSettings && streamID == 0 {
			return true
		}
	}
	return false
}

// feed accepts new bytes from the eBPF event stream and parses any complete
// HTTP/2 frames. Returns the list of fully-decoded ParsedNetworkTraffic
// messages produced (HTTPRequest or HTTPResponse).
//
// The function consumes all bytes it can; partial frames are retained in
// state.pending for the next call.
func (s *h2State) feed(data []byte, now time.Time, ifaceTag string) []akinet.ParsedNetworkTraffic {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pending = append(s.pending, data...)

	// If we haven't yet consumed the preface and it's present, skip it.
	if len(s.pending) >= len(H2Preface) && string(s.pending[:len(H2Preface)]) == H2Preface {
		s.pending = s.pending[len(H2Preface):]
	}

	var out []akinet.ParsedNetworkTraffic
	for {
		if len(s.pending) < 9 {
			return out
		}
		// Frame header (RFC 7540 §4.1):
		//   length (24): bytes 0..2
		//   type (8):    byte 3
		//   flags (8):   byte 4
		//   R+streamID:  bytes 5..8 (top bit reserved)
		length := uint32(s.pending[0])<<16 | uint32(s.pending[1])<<8 | uint32(s.pending[2])
		ftype := s.pending[3]
		fflags := s.pending[4]
		streamID := binary.BigEndian.Uint32(s.pending[5:9]) & 0x7fffffff
		if uint32(len(s.pending)) < 9+length {
			// Frame not yet complete — wait for more bytes.
			return out
		}
		payload := s.pending[9 : 9+length]

		// Process the frame.
		if pnt, ok := s.handleFrame(ftype, fflags, streamID, payload, now, ifaceTag); ok {
			out = append(out, pnt)
		}

		// Consume the frame from pending.
		s.pending = s.pending[9+length:]
	}
}

func (s *h2State) handleFrame(ftype, flags uint8, streamID uint32, payload []byte, now time.Time, ifaceTag string) (akinet.ParsedNetworkTraffic, bool) {
	switch ftype {
	case h2FrameHeaders:
		return s.handleHeaders(flags, streamID, payload, now, ifaceTag)
	case h2FrameContinuation:
		return s.handleContinuation(flags, streamID, payload, now, ifaceTag)
	case h2FrameData:
		return s.handleData(flags, streamID, payload, now, ifaceTag)
	case h2FrameSettings, h2FramePing, h2FramePriority, h2FrameRstStream,
		h2FrameGoaway, h2FrameWindowUpdate, h2FramePushPromise:
		// Frames we deliberately don't handle yet — see scope comment.
		return akinet.ParsedNetworkTraffic{}, false
	}
	return akinet.ParsedNetworkTraffic{}, false
}

// handleHeaders processes a HEADERS frame. If END_HEADERS is set we decode
// immediately; otherwise we buffer for subsequent CONTINUATION frames.
func (s *h2State) handleHeaders(flags uint8, streamID uint32, payload []byte, now time.Time, ifaceTag string) (akinet.ParsedNetworkTraffic, bool) {
	// Strip padding if present.
	if flags&h2FlagPadded != 0 && len(payload) > 0 {
		padLen := int(payload[0])
		if 1+padLen <= len(payload) {
			payload = payload[1 : len(payload)-padLen]
		}
	}
	// Strip priority block if present.
	if flags&h2FlagPriority != 0 && len(payload) >= 5 {
		payload = payload[5:]
	}

	s.headerBlock = append(s.headerBlock[:0], payload...)
	s.headersStreamID = streamID
	s.headersEndStream = flags&h2FlagEndStream != 0

	if flags&h2FlagEndHeaders != 0 {
		return s.finalizeHeaderBlock(now, ifaceTag)
	}
	return akinet.ParsedNetworkTraffic{}, false
}

func (s *h2State) handleContinuation(flags uint8, streamID uint32, payload []byte, now time.Time, ifaceTag string) (akinet.ParsedNetworkTraffic, bool) {
	if streamID != s.headersStreamID {
		// Spec violation; drop.
		return akinet.ParsedNetworkTraffic{}, false
	}
	s.headerBlock = append(s.headerBlock, payload...)
	if flags&h2FlagEndHeaders != 0 {
		return s.finalizeHeaderBlock(now, ifaceTag)
	}
	return akinet.ParsedNetworkTraffic{}, false
}

func (s *h2State) finalizeHeaderBlock(now time.Time, ifaceTag string) (akinet.ParsedNetworkTraffic, bool) {
	fields, err := s.hpack.DecodeFull(s.headerBlock)
	s.headerBlock = s.headerBlock[:0]
	if err != nil {
		return akinet.ParsedNetworkTraffic{}, false
	}

	st := s.streams[s.headersStreamID]
	if st == nil {
		st = &h2Stream{header: http.Header{}}
		s.streams[s.headersStreamID] = st
	}
	for _, f := range fields {
		switch f.Name {
		case ":method":
			st.method = f.Value
		case ":path":
			st.path = f.Value
		case ":authority":
			st.authority = f.Value
		case ":scheme":
			st.scheme = f.Value
		case ":status":
			if n, err := strconv.Atoi(f.Value); err == nil {
				st.status = n
			}
		default:
			if !isPseudoHeader(f.Name) {
				st.header.Add(f.Name, f.Value)
			}
		}
	}
	st.endStreamOnHeaders = s.headersEndStream

	// If END_STREAM was set on the HEADERS frame, the message has no body
	// and we can emit immediately.
	if s.headersEndStream {
		return s.emitStream(s.headersStreamID, now, ifaceTag)
	}
	return akinet.ParsedNetworkTraffic{}, false
}

func (s *h2State) handleData(flags uint8, streamID uint32, payload []byte, now time.Time, ifaceTag string) (akinet.ParsedNetworkTraffic, bool) {
	// Strip padding.
	if flags&h2FlagPadded != 0 && len(payload) > 0 {
		padLen := int(payload[0])
		if 1+padLen <= len(payload) {
			payload = payload[1 : len(payload)-padLen]
		}
	}

	st := s.streams[streamID]
	if st == nil {
		// DATA before HEADERS — drop.
		return akinet.ParsedNetworkTraffic{}, false
	}
	// Cap body.
	avail := h2MaxBodyBytes - len(st.body)
	if avail > 0 {
		if len(payload) > avail {
			payload = payload[:avail]
		}
		st.body = append(st.body, payload...)
	}

	if flags&h2FlagEndStream != 0 {
		return s.emitStream(streamID, now, ifaceTag)
	}
	return akinet.ParsedNetworkTraffic{}, false
}

// emitStream produces a ParsedNetworkTraffic from a completed stream and
// removes the stream state.
func (s *h2State) emitStream(streamID uint32, now time.Time, ifaceTag string) (akinet.ParsedNetworkTraffic, bool) {
	st := s.streams[streamID]
	delete(s.streams, streamID)
	if st == nil {
		return akinet.ParsedNetworkTraffic{}, false
	}

	pnt := akinet.ParsedNetworkTraffic{
		Interface:       ifaceTag,
		ObservationTime: now,
		FinalPacketTime: now,
	}

	if st.method != "" {
		// Request.
		u := &url.URL{Path: st.path}
		if st.scheme != "" {
			u.Scheme = st.scheme
		}
		if st.authority != "" {
			u.Host = st.authority
			st.header.Set("Host", st.authority)
		}
		pnt.Content = akinet.HTTPRequest{
			StreamID:   uuid.UUID(s.bidiID),
			Seq:        int(streamID),
			Method:     st.method,
			ProtoMajor: 2,
			ProtoMinor: 0,
			URL:        u,
			Host:       st.authority,
			Header:     st.header,
			Body:       memview.New(st.body),
		}
		return pnt, true
	}
	if st.status != 0 {
		pnt.Content = akinet.HTTPResponse{
			StreamID:   uuid.UUID(s.bidiID),
			Seq:        int(streamID),
			StatusCode: st.status,
			ProtoMajor: 2,
			ProtoMinor: 0,
			Header:     st.header,
			Body:       memview.New(st.body),
		}
		return pnt, true
	}
	return akinet.ParsedNetworkTraffic{}, false
}

func isPseudoHeader(name string) bool {
	return len(name) > 0 && name[0] == ':'
}

// silence unused-import warnings when only some types are referenced.
var _ = fmt.Sprintf
