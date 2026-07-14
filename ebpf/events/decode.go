// SPDX-License-Identifier: Apache-2.0

package events

import (
	"encoding/binary"
	"errors"
	"unsafe"
)

// rawEventSize is the on-the-wire size of struct ssl_event. Computed from the
// Go struct layout because the BPF side uses the same packing.
const rawEventSize = int(unsafe.Sizeof(SSLEvent{}))

// ErrShortRecord is returned by Decode when a ringbuf record is too short to
// be a valid SSLEvent.
var ErrShortRecord = errors.New("ebpf/events: ringbuf record shorter than struct ssl_event")

// Decode parses a raw byte slice from a cilium/ebpf ringbuf record into an
// SSLEvent. The bytes are read little-endian (cilium/ebpf ringbuf records on
// all supported architectures are little-endian; if we ever target a
// big-endian arch this will need a build-tagged variant).
//
// Decode allocates and returns a fresh *SSLEvent so callers can keep the
// reference past the lifetime of the ringbuf record.
func Decode(raw []byte) (*SSLEvent, error) {
	if len(raw) < rawEventSize {
		return nil, ErrShortRecord
	}

	e := &SSLEvent{}

	off := 0
	e.TimestampNS = binary.LittleEndian.Uint64(raw[off:]); off += 8
	e.PID = binary.LittleEndian.Uint32(raw[off:]);          off += 4
	e.TID = binary.LittleEndian.Uint32(raw[off:]);          off += 4
	e.SSLCtx = binary.LittleEndian.Uint64(raw[off:]);       off += 8
	e.LenCaptured = binary.LittleEndian.Uint32(raw[off:]);  off += 4
	e.LenTotal = binary.LittleEndian.Uint32(raw[off:]);     off += 4
	e.FD = int32(binary.LittleEndian.Uint32(raw[off:]));    off += 4
	e.Direction = raw[off];                                  off += 1
	off += 3 // _pad
	e.NetNS = binary.LittleEndian.Uint32(raw[off:]);        off += 4

	n := int(e.LenCaptured)
	if n > MaxEventPayload {
		n = MaxEventPayload
	}
	if off+n > len(raw) {
		return nil, ErrShortRecord
	}
	copy(e.Payload[:n], raw[off:off+n])

	return e, nil
}
