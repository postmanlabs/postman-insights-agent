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
//
// Within a version, writers set the reserved bytes and undefined flag bits to
// zero, and readers ignore them. So a later agent can add an optional field in
// the reserved bytes, with a new flag bit saying it is set, and older readers
// still accept its frames. Anything a reader must understand to read a frame
// correctly needs a new version.
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
	OpSend      uint8 = 1 // plaintext the JVM sent (consumed by SSLEngine.wrap)
	OpRecv      uint8 = 2 // plaintext the JVM received (produced by SSLEngine.unwrap); empty at a connection's first unwrap, which ties it to its socket
	OpHeartbeat uint8 = 3 // agent liveness and status; payload is key=value lines
	OpClose     uint8 = 4 // connection closed; no payload
	OpAddress   uint8 = 5 // the connection's addresses, from the agent; payload is an Address (AddressSize bytes)
)

// Flag bits.
const (
	FlagRoleKnown  uint16 = 0x1 // the client/server role is known
	FlagClientMode uint16 = 0x2 // the JVM is the TLS client (valid with FlagRoleKnown)
	// 0x4 is free: no writer has set it.
	// FlagSocket marks a blocking socket's frames: the connection's addresses
	// come in an ADDRESS frame, never from the thread's socket reads.
	FlagSocket uint16 = 0x8
	// FlagBeforeWrite, on a SEND, says the frame's bytes are written to the
	// socket after it, by the thread that sent it when the framework writes
	// inline (a wrap). Only then is a connection not yet tied tied to the
	// thread's next socket write.
	FlagBeforeWrite uint16 = 0x10
)

// ConnIDTag is set on a Java connection id when it becomes an ssl_event's
// ssl_ctx. User-space pointers never set bit 63, so Java ids can never collide
// with real SSL* pointers from the libssl uprobes.
const ConnIDTag uint64 = 1 << 63

// SSLCtx returns the ssl_ctx the kernel stamps on events for connID.
func SSLCtx(connID uint64) uint64 { return connID | ConnIDTag }

// IsJavaSSLCtx reports whether an ssl_ctx came from a Java frame.
func IsJavaSSLCtx(sslCtx uint64) bool { return sslCtx&ConnIDTag != 0 }

// Header field offsets. Multi-byte fields are little-endian. The reserved
// bytes run from offReserved to offTotalLen.
const (
	offVersion    = 0
	offOp         = 1
	offFlags      = 2
	offPayloadLen = 4
	offConnID     = 8
	offReserved   = 16
	offTotalLen   = 36
)

// Frame is one decoded frame.
type Frame struct {
	Version uint8
	Op      uint8
	Flags   uint16
	// ConnID is unique per connection within the JVM. Ids count from a
	// random start below 2^62, so a JVM that reuses an exited one's PID
	// does not reuse its ids.
	ConnID uint64
	// TotalLen is how many bytes the engine call produced or consumed. It is
	// larger than len(Payload) when the agent truncated the payload to its
	// capture cap.
	TotalLen uint32
	Payload  []byte
}

// Append encodes f onto b and returns the extended slice. The payload length
// is taken from len(f.Payload); the reserved bytes are zero.
func (f Frame) Append(b []byte) []byte {
	var h [HeaderSize]byte
	h[offVersion] = f.Version
	h[offOp] = f.Op
	binary.LittleEndian.PutUint16(h[offFlags:], f.Flags)
	binary.LittleEndian.PutUint32(h[offPayloadLen:], uint32(len(f.Payload)))
	binary.LittleEndian.PutUint64(h[offConnID:], f.ConnID)
	binary.LittleEndian.PutUint32(h[offTotalLen:], f.TotalLen)
	b = append(b, h[:]...)
	return append(b, f.Payload...)
}

// Errors returned by Parse.
var (
	ErrShort       = errors.New("javatls: frame shorter than its header")
	ErrVersion     = errors.New("javatls: unsupported frame version")
	ErrOp          = errors.New("javatls: unknown frame op")
	ErrLength      = errors.New("javatls: payload length does not match the write length")
	ErrTotalLength = errors.New("javatls: total length smaller than payload length")
	ErrAddress     = errors.New("javatls: malformed ADDRESS payload")
)

// Parse decodes one frame from a whole positional write, applying the same
// checks as the kernel program (java_tls.bpf.c), so the two accept exactly the
// same frames. It ignores the reserved bytes and undefined flag bits (the
// returned Flags keep them). The returned payload aliases b.
func Parse(b []byte) (Frame, error) {
	if len(b) < HeaderSize {
		return Frame{}, ErrShort
	}
	f := Frame{
		Version:  b[offVersion],
		Op:       b[offOp],
		Flags:    binary.LittleEndian.Uint16(b[offFlags:]),
		ConnID:   binary.LittleEndian.Uint64(b[offConnID:]),
		TotalLen: binary.LittleEndian.Uint32(b[offTotalLen:]),
	}
	if f.Version != Version1 {
		return Frame{}, fmt.Errorf("%w: %d", ErrVersion, f.Version)
	}
	if f.Op < OpSend || f.Op > OpAddress {
		return Frame{}, fmt.Errorf("%w: %d", ErrOp, f.Op)
	}
	payloadLen := binary.LittleEndian.Uint32(b[offPayloadLen:])
	if uint64(payloadLen)+HeaderSize != uint64(len(b)) {
		return Frame{}, fmt.Errorf("%w: payload_len=%d, write=%d", ErrLength, payloadLen, len(b))
	}
	if f.TotalLen < payloadLen {
		return Frame{}, fmt.Errorf("%w: total_len=%d, payload_len=%d", ErrTotalLength, f.TotalLen, payloadLen)
	}
	f.Payload = b[HeaderSize:]
	if f.Op == OpAddress {
		if _, err := ParseAddress(f.Payload); err != nil {
			return Frame{}, err
		}
	}
	return f, nil
}

// AddressSize is the size of an ADDRESS frame's payload.
const AddressSize = 40

// Address families in an ADDRESS payload (the kernel's AF_INET and AF_INET6).
const (
	addressFamilyInet  = 2
	addressFamilyInet6 = 10
)

// Address is an ADDRESS frame's payload: the connection's TCP addresses,
// which the agent knows for a blocking socket. It has the layout of the
// kernel's struct conn_tuple, which the kernel copies it into:
//
//	 0  u8      family       2 (IPv4) or 10 (IPv6, including IPv4-mapped)
//	 1  u8[3]   zero
//	 4  u16     local_port   little-endian
//	 6  u16     remote_port  little-endian
//	 8  u8[16]  local_addr   network byte order; IPv4 in the first 4 bytes, the rest zero
//	24  u8[16]  remote_addr  the same
type Address struct {
	Local, Remote netip.AddrPort
}

// Append encodes a onto b and returns the extended slice: family 2 when both
// addresses are IPv4 (or IPv4-mapped), else 10, with IPv4 addresses mapped.
func (a Address) Append(b []byte) []byte {
	var p [AddressSize]byte
	local, remote := a.Local.Addr().Unmap(), a.Remote.Addr().Unmap()
	binary.LittleEndian.PutUint16(p[4:], a.Local.Port())
	binary.LittleEndian.PutUint16(p[6:], a.Remote.Port())
	if local.Is4() && remote.Is4() {
		p[0] = addressFamilyInet
		l, r := local.As4(), remote.As4()
		copy(p[8:], l[:])
		copy(p[24:], r[:])
	} else {
		p[0] = addressFamilyInet6
		l, r := local.As16(), remote.As16()
		copy(p[8:], l[:])
		copy(p[24:], r[:])
	}
	return append(b, p[:]...)
}

// ParseAddress decodes an ADDRESS frame's payload, applying the kernel's
// checks: the size, a known family, zero padding, and zero bytes after an
// IPv4 address. IPv4-mapped addresses are unmapped.
func ParseAddress(p []byte) (Address, error) {
	if len(p) != AddressSize {
		return Address{}, fmt.Errorf("%w: %d bytes, want %d", ErrAddress, len(p), AddressSize)
	}
	if p[1] != 0 || p[2] != 0 || p[3] != 0 {
		return Address{}, fmt.Errorf("%w: padding is not zero", ErrAddress)
	}
	var local, remote netip.Addr
	switch p[0] {
	case addressFamilyInet:
		var zero [12]byte
		if [12]byte(p[12:24]) != zero || [12]byte(p[28:40]) != zero {
			return Address{}, fmt.Errorf("%w: IPv4 address with trailing bytes", ErrAddress)
		}
		local, remote = netip.AddrFrom4([4]byte(p[8:12])), netip.AddrFrom4([4]byte(p[24:28]))
	case addressFamilyInet6:
		local, remote = netip.AddrFrom16([16]byte(p[8:24])).Unmap(), netip.AddrFrom16([16]byte(p[24:40])).Unmap()
	default:
		return Address{}, fmt.Errorf("%w: family %d", ErrAddress, p[0])
	}
	return Address{
		Local:  netip.AddrPortFrom(local, binary.LittleEndian.Uint16(p[4:])),
		Remote: netip.AddrPortFrom(remote, binary.LittleEndian.Uint16(p[6:])),
	}, nil
}
