// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package events

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// Reader pulls records out of the BPF ringbuf, decodes them into SSLEvents,
// and forwards them on the Out channel.
type Reader struct {
	rb  *ringbuf.Reader
	Out chan *SSLEvent

	// Counters exported for telemetry.
	EventsRead   atomic.Uint64
	EventsLost   atomic.Uint64
	DecodeErrors atomic.Uint64
}

// NewReader wraps a BPF ringbuf map. Caller owns the map's lifecycle; closing
// the Reader closes the underlying ringbuf.Reader but not the map.
//
// The map argument is the *ebpf.Map returned by loader.EventsMap(). Buffer is
// the capacity of the Out channel — pick something large enough to absorb
// bursts (1024-8192 is reasonable).
func NewReader(m *ebpf.Map, bufferSize int) (*Reader, error) {
	if m == nil {
		return nil, errors.New("ebpf/events: nil ringbuf map")
	}
	rb, err := ringbuf.NewReader(m)
	if err != nil {
		return nil, fmt.Errorf("ebpf/events: open ringbuf: %w", err)
	}
	return &Reader{
		rb:  rb,
		Out: make(chan *SSLEvent, bufferSize),
	}, nil
}

// Run reads from the ringbuf until ctx is cancelled or an unrecoverable error
// occurs. It closes Out before returning.
func (r *Reader) Run(ctx context.Context) error {
	defer close(r.Out)

	// Make Read() unblock when ctx is cancelled.
	go func() {
		<-ctx.Done()
		_ = r.rb.Close()
	}()

	for {
		rec, err := r.rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("ebpf/events: ringbuf read: %w", err)
		}

		r.EventsRead.Add(1)
		// NOTE: ringbuf has no per-record lost count (that's a perf-event API).
		// Drops are visible via bpf_ringbuf_query() on the map (BPF_RB_AVAIL_DATA /
		// BPF_RB_RING_SIZE) and surfaced via the telemetry counters on Loader.

		ev, err := Decode(rec.RawSample)
		if err != nil {
			r.DecodeErrors.Add(1)
			continue
		}

		select {
		case r.Out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
}

// Close releases the ringbuf reader. Safe to call multiple times.
func (r *Reader) Close() error { return r.rb.Close() }
