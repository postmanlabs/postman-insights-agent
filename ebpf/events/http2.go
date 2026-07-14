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
// Scope (minimum viable implementation):
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
	headerBlock      []byte
	headersStreamID  uint32
	headersEndStream bool

	// Per-stream state, keyed by stream ID.
	streams map[uint32]*h2Stream

	// conn is the shared per-TLS-connection state. The witness namespace
	// (bidiID) lives here rather than being snapshotted, so that when the
	// adapter regenerates conn.bidiID for a reused SSL* pointer, BOTH direction
	// decoders emit under the new id and request/response still pair. Read the
	// id via s.bidiID().
	conn *tlsConnState

	// epoch is the conn.h2Epoch value this decoder last reset at. When the
	// shared epoch advances (a new connection began on the reused SSL*, detected
	// via the client preface on either direction), feed() resets this decoder's
	// per-connection state so we don't carry stream/HPACK state across
	// connections. See tlsConnState.h2Epoch.
	epoch uint64

	// hpackErrors counts HEADERS+CONTINUATION decode failures. Non-zero on
	// a flow strongly suggests we attached mid-connection and missed the
	// dynamic-table state. Exposed via HPACKErrors() for telemetry.
	hpackErrors uint64

	// hpackDesynced latches true after the first HPACK decode failure. A
	// decode failure proves the encoder's dynamic table diverged from ours
	// (we attached mid-connection and missed the inserts that populated it).
	// This is UNRECOVERABLE: we can never reconstruct entries we never saw.
	// Critically, a desynced table can still decode later blocks *without
	// error* yet return the WRONG header values (a stale/mis-indexed dynamic
	// entry), which would emit corrupt method/path/status into the UI. So once
	// desynced we stop decoding HEADERS on this connection entirely and emit
	// nothing further from it — dropping the connection is strictly safer than
	// risking silently-wrong data. New connections (caught at their preface)
	// are unaffected and decode normally.
	hpackDesynced bool
}

// HPACKErrors returns the number of HEADERS decode failures on this flow.
// Use it to detect the mid-connection-attach failure mode.
func (s *h2State) HPACKErrors() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hpackErrors
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

	// gRPC flag (set when content-type starts with application/grpc).
	// When true, DATA frame payloads are parsed as length-prefixed gRPC
	// messages (1 byte compressed flag + 4 bytes BE length + N bytes msg).
	isGRPC bool

	// gRPC message reassembly: protobuf-message bytes can be split across
	// DATA frames; we buffer here and split out one message at a time.
	grpcMessages [][]byte
}

// h2MaxBodyBytes bounds the body bytes we'll buffer per stream. Mirrors
// adapter's MaxPendingPerFlow.
const h2MaxBodyBytes = 1 * 1024 * 1024

func newH2State(conn *tlsConnState) *h2State {
	return &h2State{
		hpack:   hpack.NewDecoder(4096, nil),
		streams: map[uint32]*h2Stream{},
		conn:    conn,
	}
}

// bidiID returns the live per-connection witness namespace. It is read fresh
// (not snapshotted) so a mid-life regeneration by the adapter is reflected in
// every subsequently emitted stream on this connection.
func (s *h2State) bidiID() akinet.TCPBidiID {
	return s.conn.bidiID
}

// resetForNewConnection clears the per-connection decode state when the reused
// SSL* pointer rolls to a new connection. HPACK state and stream state are
// strictly per-connection (RFC 7540/7541), so carrying them across connections
// would desync the dynamic table and collide stream IDs. It intentionally does
// NOT touch s.pending (the caller is mid-parse) or the shared conn/epoch.
func (s *h2State) resetForNewConnection() {
	s.hpack = hpack.NewDecoder(4096, nil)
	s.streams = map[uint32]*h2Stream{}
	s.headerBlock = s.headerBlock[:0]
	s.headersStreamID = 0
	s.headersEndStream = false
	s.hpackDesynced = false
}

// IsHTTP2Preface returns true if the given bytes start with the HTTP/2
// connection preface or look like a SETTINGS frame at stream_id=0 (which is
// what the server sends back as its half of the preface).
// isH2ClientPreface reports whether b begins with the HTTP/2 client connection
// preface ("PRI * HTTP/2.0..."). Unlike IsHTTP2Preface it does NOT match the
// server-side SETTINGS frame, so it fires exactly once per connection (on the
// client-write side). The adapter uses it to regenerate the per-connection
// bidiID exactly once when an SSL* pointer is reused for a new connection.
func isH2ClientPreface(b []byte) bool {
	return len(b) >= len(H2Preface) && string(b[:len(H2Preface)]) == H2Preface
}

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

// IsHTTP2Frame is a heuristic for detecting an HTTP/2 frame header mid-
// stream. We use this when we attach to a process AFTER the preface has
// already been exchanged (common for gotls, since the TLS handshake +
// preface complete before our uprobes catch the first non-handshake
// read/write).
//
// An HTTP/2 frame header (RFC 7540 §4.1) is 9 bytes:
//
//	length(3) | type(1) | flags(1) | R+streamID(4, top bit reserved=0)
//
// We require:
//   - at least 9 bytes,
//   - type byte in [0, 9] (the defined HTTP/2 frame types),
//   - the reserved top bit of stream-id is zero,
//   - declared length is reasonable (<= 16 MiB, the HTTP/2 max frame size
//     ceiling is 2^24-1, but practical SETTINGS_MAX_FRAME_SIZE never
//     exceeds 16 MiB), and
//   - if there's a second frame header after the first, IT also passes the
//     same type-byte test. Two valid frame headers back-to-back is a
//     strong signal we're looking at HTTP/2 rather than coincidentally-
//     shaped HTTP/1.
func IsHTTP2Frame(b []byte) bool {
	if len(b) < 9 {
		return false
	}
	if !looksLikeH2FrameHeader(b) {
		return false
	}
	length := uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
	// If we have a second frame after the first, validate it too.
	offset := 9 + int(length)
	if offset+9 <= len(b) {
		return looksLikeH2FrameHeader(b[offset:])
	}
	// Only one frame visible — single-header heuristic.
	return true
}

func looksLikeH2FrameHeader(b []byte) bool {
	if len(b) < 9 {
		return false
	}
	typ := b[3]
	if typ > h2FrameContinuation {
		return false
	}
	if b[5]&0x80 != 0 {
		// Reserved high bit of stream-id must be zero.
		return false
	}
	length := uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
	if length > 16<<20 {
		return false
	}
	streamID := binary.BigEndian.Uint32(b[5:9]) & 0x7fffffff
	// RFC 7540 stream-id requirements per frame type. Rejecting these
	// kills false positives on all-zero / random byte streams.
	switch typ {
	case h2FrameData, h2FrameHeaders, h2FramePriority, h2FrameRstStream,
		h2FramePushPromise, h2FrameContinuation:
		if streamID == 0 {
			return false
		}
	case h2FrameSettings, h2FramePing, h2FrameGoaway:
		if streamID != 0 {
			return false
		}
	}
	return true
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

	// A client preface at the start of pending marks the beginning of a
	// connection. Because a reused SSL* keeps this same h2State alive across
	// connections, seeing a preface again means a NEW connection has begun. If
	// the conn has already carried H2 traffic, roll the shared witness namespace
	// (bump epoch + regenerate bidiID) so this connection's stream 1/3/5... do
	// not collide with the previous connection's on witness ID. Then reset our
	// per-connection decode state (fresh HPACK context — the peer's dynamic
	// table also resets per connection — and empty stream map).
	if isH2ClientPreface(s.pending) {
		if s.conn.h2Seen {
			s.conn.h2Epoch++
			s.conn.bidiID = akinet.TCPBidiID(uuid.New())
		}
		s.conn.h2Seen = true
		s.epoch = s.conn.h2Epoch
		s.resetForNewConnection()
		s.pending = s.pending[len(H2Preface):]
	}

	// Peer direction (the one that does NOT carry the client preface, e.g. the
	// server's SETTINGS side) picks up a connection roll lazily: when it sees
	// the shared epoch has advanced past the one it last reset at, it resets its
	// own per-connection decode state so it decodes the new connection under the
	// new (regenerated) bidiID and a fresh HPACK context.
	if s.epoch != s.conn.h2Epoch {
		s.epoch = s.conn.h2Epoch
		s.resetForNewConnection()
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
	// Once this connection's HPACK context has proven desynced, do not decode
	// further HEADERS: the dynamic table is unreliable, so a "successful" decode
	// could still yield wrong values. Consume the block and emit nothing. Frame
	// parsing (which is length-prefixed and independent of HPACK) continues
	// unaffected, so we stay in sync at the frame level.
	if s.hpackDesynced {
		s.headerBlock = s.headerBlock[:0]
		return akinet.ParsedNetworkTraffic{}, false
	}

	fields, err := s.hpack.DecodeFull(s.headerBlock)
	s.headerBlock = s.headerBlock[:0]
	if err != nil {
		// Mid-connection attach: the encoder's HPACK dynamic table was built
		// across HEADERS frames we never observed, so it has irrecoverably
		// diverged from ours. Latch desync so we stop trusting this connection
		// (see hpackDesynced). Counter is exposed via HPACKErrors() for
		// telemetry.
		s.hpackErrors++
		s.hpackDesynced = true
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
			if f.Name == "content-type" && len(f.Value) >= len("application/grpc") &&
				f.Value[:len("application/grpc")] == "application/grpc" {
				st.isGRPC = true
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

	// For gRPC streams, peel off as many complete length-prefixed messages
	// as st.body contains. Each message becomes its own entry in
	// st.grpcMessages so the downstream emitter can attach the
	// per-message bytes to its event. Partial trailing bytes stay in
	// st.body until the next DATA frame arrives.
	if st.isGRPC {
		for {
			if len(st.body) < 5 {
				break
			}
			compressedFlag := st.body[0]
			_ = compressedFlag // surfaced via grpc-encoding header; we just demux
			msgLen := binary.BigEndian.Uint32(st.body[1:5])
			if uint32(len(st.body)) < 5+msgLen {
				break
			}
			msg := append([]byte(nil), st.body[5:5+msgLen]...)
			st.grpcMessages = append(st.grpcMessages, msg)
			st.body = st.body[5+msgLen:]
		}
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

	// For gRPC, the "body" we attach to the emitted event is the
	// concatenation of the protobuf-message payloads with their
	// length-prefix framing stripped. This matches what an application-
	// layer gRPC handler observes (the protobuf bytes, not the framing).
	// We also stamp two synthetic headers so downstream observability can
	// tell a gRPC event apart from a plain h2 event:
	//   x-pi-grpc-messages: <count>
	//   x-pi-grpc-total-bytes: <bytes>
	body := st.body
	if st.isGRPC {
		total := 0
		for _, m := range st.grpcMessages {
			total += len(m)
		}
		body = make([]byte, 0, total)
		for _, m := range st.grpcMessages {
			body = append(body, m...)
		}
		st.header.Set("X-Pi-Grpc-Messages", strconv.Itoa(len(st.grpcMessages)))
		st.header.Set("X-Pi-Grpc-Total-Bytes", strconv.Itoa(total))
	}

	if st.method != "" {
		// Request.
		st.finalizeRequestMeta()
		u := &url.URL{Path: st.path}
		if st.scheme != "" {
			u.Scheme = st.scheme
		}
		if st.authority != "" {
			u.Host = st.authority
			if st.header.Get("Host") == "" {
				st.header.Set("Host", st.authority)
			}
		}
		pnt.Content = akinet.HTTPRequest{
			StreamID:   uuid.UUID(s.bidiID()),
			Seq:        int(streamID),
			Method:     st.method,
			ProtoMajor: 2,
			ProtoMinor: 0,
			URL:        u,
			Host:       st.authority,
			Header:     st.header,
			Body:       memview.New(body),
		}
		return pnt, true
	}
	if st.status != 0 {
		pnt.Content = akinet.HTTPResponse{
			StreamID:   uuid.UUID(s.bidiID()),
			Seq:        int(streamID),
			StatusCode: st.status,
			ProtoMajor: 2,
			ProtoMinor: 0,
			Header:     st.header,
			Body:       memview.New(body),
		}
		return pnt, true
	}
	return akinet.ParsedNetworkTraffic{}, false
}

// finalizeRequestMeta backfills pseudo-headers gRPC clients sometimes omit
// from literal HPACK fields (relying on the dynamic table or a plain Host
// header instead).
func (st *h2Stream) finalizeRequestMeta() {
	if st.authority == "" {
		if h := st.header.Get("Host"); h != "" {
			st.authority = h
		}
	}
	if st.scheme == "" && st.isGRPC {
		st.scheme = "https"
	}
}

func isPseudoHeader(name string) bool {
	return len(name) > 0 && name[0] == ':'
}

