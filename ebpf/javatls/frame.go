// SPDX-License-Identifier: Apache-2.0

// Package javatls holds the contract between the Postman Java agent (running
// inside customer JVMs) and the Insights agent: the frame format the Java
// agent hands to the kernel, and the names both sides agree on.
//
// The frame format has three copies that must stay in sync:
//   - ebpf/programs/java_frame.h (kernel; checked against this file by tests)
//   - this file
//   - java-agent/src/main/java/com/postman/insights/agent/bootstrap/Frame.java
//
// testdata/frames-v1.json holds example frames that the Go and Java tests both
// check, so a change on one side that the other side does not make fails a
// test. Any change to the format updates all three copies and the examples in
// one change, and adds a new version instead of changing an existing one: an
// agent loaded into a JVM cannot be unloaded, so a newer Insights agent must
// keep reading older agents' frames until those JVMs restart.
package javatls

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// Magic is the write offset that marks a frame ("PMINSIGH" as a little-endian
// uint64). It is positive and far beyond any real file offset, so no
// legitimate positional write matches it.
const Magic uint64 = 0x504D494E53494748

// Version1 is the only frame version so far.
const Version1 uint8 = 1

// HeaderSize is the number of bytes before the payload.
const HeaderSize = 40

// Op values.
const (
	OpSend  uint8 = 1 // plaintext the JVM sent (consumed by SSLEngine.wrap)
	OpRecv  uint8 = 2 // plaintext the JVM received (produced by SSLEngine.unwrap)
	OpHello uint8 = 3 // agent heartbeat; payload is key=value lines
	OpClose uint8 = 4 // connection closed; no payload
)

// Flag bits.
const (
	FlagRoleKnown  uint16 = 0x1 // the client/server role is known
	FlagClientMode uint16 = 0x2 // the JVM is the TLS client (valid with FlagRoleKnown)
	FlagPeerKnown  uint16 = 0x4 // PeerAddr and PeerPort are set
)

// ConnIDTag is set on a Java connection id when it becomes an ssl_event's
// ssl_ctx. User-space pointers never set bit 63, so Java ids can never collide
// with real SSL* pointers from the libssl uprobes.
const ConnIDTag uint64 = 1 << 63

// SSLCtx returns the ssl_ctx the kernel stamps on events for connID.
func SSLCtx(connID uint64) uint64 { return connID | ConnIDTag }

// IsJavaSSLCtx reports whether an ssl_ctx came from a Java frame.
func IsJavaSSLCtx(sslCtx uint64) bool { return sslCtx&ConnIDTag != 0 }

// Header field offsets. Multi-byte fields are little-endian, except the peer
// port, which is in network byte order.
const (
	offVersion    = 0
	offOp         = 1
	offFlags      = 2
	offPayloadLen = 4
	offConnID     = 8
	offPeerAddr   = 16
	offPeerPort   = 32
	offReserved   = 34
	offTotalLen   = 36
)

// Frame is one decoded frame.
type Frame struct {
	Version uint8
	Op      uint8
	Flags   uint16
	ConnID  uint64
	// PeerAddr is the peer's address as 16 bytes (IPv4 addresses are
	// IPv4-mapped). The zero value means unknown.
	PeerAddr [16]byte
	PeerPort uint16
	// TotalLen is how many bytes the engine call produced or consumed. It is
	// larger than len(Payload) when the agent truncated the payload to its
	// capture cap.
	TotalLen uint32
	Payload  []byte
}

// Peer returns the peer address and port, and whether they are known.
func (f Frame) Peer() (netip.AddrPort, bool) {
	if f.Flags&FlagPeerKnown == 0 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(netip.AddrFrom16(f.PeerAddr).Unmap(), f.PeerPort), true
}

// Append encodes f onto b and returns the extended slice. The payload length
// is taken from len(f.Payload).
func (f Frame) Append(b []byte) []byte {
	var h [HeaderSize]byte
	h[offVersion] = f.Version
	h[offOp] = f.Op
	binary.LittleEndian.PutUint16(h[offFlags:], f.Flags)
	binary.LittleEndian.PutUint32(h[offPayloadLen:], uint32(len(f.Payload)))
	binary.LittleEndian.PutUint64(h[offConnID:], f.ConnID)
	copy(h[offPeerAddr:offPeerPort], f.PeerAddr[:])
	binary.BigEndian.PutUint16(h[offPeerPort:], f.PeerPort)
	binary.LittleEndian.PutUint32(h[offTotalLen:], f.TotalLen)
	b = append(b, h[:]...)
	return append(b, f.Payload...)
}

// Errors returned by Parse.
var (
	ErrShort        = errors.New("javatls: frame shorter than its header")
	ErrVersion      = errors.New("javatls: unsupported frame version")
	ErrOp           = errors.New("javatls: unknown frame op")
	ErrLength       = errors.New("javatls: payload length does not match the write length")
	ErrTotalLength  = errors.New("javatls: total length smaller than payload length")
	ErrReservedBits = errors.New("javatls: reserved field is not zero")
)

// Parse decodes one frame from a whole positional write, applying the same
// checks as the kernel program (java_tls.bpf.c), so the two accept exactly the
// same frames. The returned payload aliases b.
func Parse(b []byte) (Frame, error) {
	if len(b) < HeaderSize {
		return Frame{}, ErrShort
	}
	f := Frame{
		Version:  b[offVersion],
		Op:       b[offOp],
		Flags:    binary.LittleEndian.Uint16(b[offFlags:]),
		ConnID:   binary.LittleEndian.Uint64(b[offConnID:]),
		PeerPort: binary.BigEndian.Uint16(b[offPeerPort:]),
		TotalLen: binary.LittleEndian.Uint32(b[offTotalLen:]),
	}
	copy(f.PeerAddr[:], b[offPeerAddr:offPeerPort])
	if f.Version != Version1 {
		return Frame{}, fmt.Errorf("%w: %d", ErrVersion, f.Version)
	}
	if f.Op < OpSend || f.Op > OpClose {
		return Frame{}, fmt.Errorf("%w: %d", ErrOp, f.Op)
	}
	if binary.LittleEndian.Uint16(b[offReserved:]) != 0 {
		return Frame{}, ErrReservedBits
	}
	payloadLen := binary.LittleEndian.Uint32(b[offPayloadLen:])
	if uint64(payloadLen)+HeaderSize != uint64(len(b)) {
		return Frame{}, fmt.Errorf("%w: payload_len=%d, write=%d", ErrLength, payloadLen, len(b))
	}
	if f.TotalLen < payloadLen {
		return Frame{}, fmt.Errorf("%w: total_len=%d, payload_len=%d", ErrTotalLength, f.TotalLen, payloadLen)
	}
	f.Payload = b[HeaderSize:]
	return f, nil
}
