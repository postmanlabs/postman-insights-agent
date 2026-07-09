// SPDX-License-Identifier: Apache-2.0
//
// Stub Reader for builds without the `insights_bpf` tag, and for non-Linux
// platforms.

//go:build !linux || !insights_bpf

package events

import (
	"context"
	"errors"
	"sync/atomic"
)

// ErrUnsupported is returned by NewReader when this binary lacks eBPF support.
var ErrUnsupported = errors.New("ebpf/events: ringbuf reader not compiled into this binary")

// Reader is a no-op stub. Out is non-nil but never receives events.
type Reader struct {
	Out          chan *SSLEvent
	EventsRead   atomic.Uint64
	EventsLost   atomic.Uint64
	DecodeErrors atomic.Uint64
}

// NewReader on stub builds takes `any` for the map so we don't need to import
// cilium/ebpf when this stub compiles.
func NewReader(_ any, bufferSize int) (*Reader, error) {
	return nil, ErrUnsupported
}

func (r *Reader) Run(_ context.Context) error { return ErrUnsupported }
func (r *Reader) Close() error                 { return nil }
