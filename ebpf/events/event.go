// Package events defines the Go-side mirror of struct ssl_event in
// ebpf/programs/event.h and the ring-buffer reader that consumes it.
package events

import "time"

// Direction values must match DIR_EGRESS / DIR_INGRESS in event.h.
const (
	DirEgress  uint8 = 0 // local process is sending (SSL_write)
	DirIngress uint8 = 1 // local process is receiving (SSL_read)
)

// MaxEventPayload mirrors MAX_EVENT_PAYLOAD in event.h (4096). Used to size the
// payload byte array when decoding ringbuf records.
const MaxEventPayload = 4096

// SSLEvent is the Go form of `struct ssl_event` emitted by libssl.bpf.c.
//
// Field order, sizes, and padding MUST match the C struct exactly. The
// size is verified at compile time via unsafe.Sizeof in decode.go.
type SSLEvent struct {
	TimestampNS uint64 // bpf_ktime_get_ns() — boot-time-relative
	PID         uint32 // tgid (Linux "process id")
	TID         uint32 // pid  (Linux "thread id")
	SSLCtx      uint64 // SSL* pointer — opaque per-connection identifier
	LenCaptured uint32 // bytes actually copied into Payload
	LenTotal    uint32 // total bytes the SSL syscall reported
	FD          int32  // socket fd associated with the SSL*, or -1 if unknown
	Direction   uint8  // DirEgress or DirIngress
	_           [3]byte
	NetNS       uint32 // network-namespace inode (routing key; matches /proc/<pid>/ns/net)
	Payload     [MaxEventPayload]byte
}

// Time returns the event timestamp as a Go time.Time. The BPF timestamp is
// CLOCK_MONOTONIC relative to system boot; we adjust to wall clock using the
// offset captured when the loader started.
func (e *SSLEvent) Time(monotonicEpoch time.Time) time.Time {
	return monotonicEpoch.Add(time.Duration(e.TimestampNS))
}

// FlowKey identifies a "virtual TCP flow" for the purpose of feeding bytes
// into akinet parsers. We synthesize one flow per (PID, SSLCtx, Direction)
// triple, since within a process the SSL* pointer uniquely identifies a TLS
// connection and the direction picks between request-side and response-side
// of that connection.
type FlowKey struct {
	PID       uint32
	SSLCtx    uint64
	Direction uint8
}

// Key extracts the FlowKey for an event.
func (e *SSLEvent) Key() FlowKey {
	return FlowKey{PID: e.PID, SSLCtx: e.SSLCtx, Direction: e.Direction}
}

// Bytes returns the captured plaintext as a slice into the event's payload
// array. The slice MUST NOT outlive the event — the caller copies if needed.
func (e *SSLEvent) Bytes() []byte {
	n := int(e.LenCaptured)
	if n > len(e.Payload) {
		n = len(e.Payload)
	}
	return e.Payload[:n]
}

// Truncated reports whether the BPF side dropped bytes that did not fit in
// the per-event payload cap. The full size is preserved in LenTotal so the
// pipeline can record-truncated metadata.
func (e *SSLEvent) Truncated() bool {
	return e.LenTotal > e.LenCaptured
}
