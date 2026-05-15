// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"

	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// JavaTLSCollector manages the single-kprobe java_tls program plus a reader
// pump that feeds events into a shared adapter. Compared to GoTLSCollector
// this is much simpler: one global attach point, no per-target binary
// inspection.
type JavaTLSCollector struct {
	loader  *loader.JavaTLSLoader
	reader  *events.Reader
	adapter *events.Adapter
	rawTap  bool

	mu      sync.Mutex
	kprobe  link.Link
	closed  bool
}

// NewJavaTLSCollector loads the BPF program and constructs a reader feeding
// the supplied adapter. Caller MUST call Attach before Run.
func NewJavaTLSCollector(
	maxCaptureBytes uint32,
	enforceAllowlist bool,
	adapter *events.Adapter,
) (*JavaTLSCollector, error) {
	return NewJavaTLSCollectorWithRawTap(maxCaptureBytes, enforceAllowlist, adapter, false)
}

// NewJavaTLSCollectorWithRawTap is the diagnostic variant that dumps raw
// decoded bytes to stderr.
func NewJavaTLSCollectorWithRawTap(
	maxCaptureBytes uint32,
	enforceAllowlist bool,
	adapter *events.Adapter,
	rawTap bool,
) (*JavaTLSCollector, error) {
	if adapter == nil {
		return nil, fmt.Errorf("ebpf: JavaTLSCollector requires an Adapter")
	}
	l, err := loader.LoadJavaTLS(maxCaptureBytes, enforceAllowlist)
	if err != nil {
		return nil, err
	}
	r, err := events.NewReader(l.EventsMap(), 4096)
	if err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("ebpf: java_tls ringbuf reader: %w", err)
	}
	return &JavaTLSCollector{
		loader:  l,
		reader:  r,
		adapter: adapter,
		rawTap:  rawTap,
	}, nil
}

// Attach attaches the kprobe to sys_ioctl. Idempotent — second call is a
// no-op.
func (c *JavaTLSCollector) Attach() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.kprobe != nil {
		return nil
	}
	lnk, err := c.loader.Attach()
	if err != nil {
		return err
	}
	c.kprobe = lnk
	printer.Stderr.Infof("ebpf: attached java_tls kprobe sys_ioctl\n")
	return nil
}

// AddTargetPID delegates to the underlying loader.
func (c *JavaTLSCollector) AddTargetPID(pid uint32) error {
	return c.loader.AddTargetPID(pid)
}

// RemoveTargetPID delegates to the underlying loader.
func (c *JavaTLSCollector) RemoveTargetPID(pid uint32) error {
	return c.loader.RemoveTargetPID(pid)
}

// Run pumps events from the ringbuf into the adapter until ctx is cancelled.
func (c *JavaTLSCollector) Run(ctx context.Context, monoEpoch time.Time) {
	readerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		if err := c.reader.Run(readerCtx); err != nil {
			printer.Errorf("ebpf: java_tls reader stopped: %v\n", err)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-c.reader.Out:
			if !ok {
				return
			}
			if c.rawTap {
				n := len(ev.Bytes())
				if n > 16 {
					n = 16
				}
				printer.Stderr.Infof("javatls-raw: pid=%d ssl_ctx=0x%x len=%d/%d dir=%d head=%x\n",
					ev.PID, ev.SSLCtx, ev.LenCaptured, ev.LenTotal, ev.Direction,
					ev.Bytes()[:n])
			}
			c.adapter.Feed(ev, monoEpoch)
		}
	}
}

// Close detaches the kprobe, closes the reader, and frees BPF resources.
func (c *JavaTLSCollector) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	lnk := c.kprobe
	c.kprobe = nil
	c.mu.Unlock()
	if lnk != nil {
		_ = lnk.Close()
	}
	_ = c.reader.Close()
	return c.loader.Close()
}

// Counter accessors for diagnostics.
func (c *JavaTLSCollector) CounterEmitted() uint64     { v, _ := c.loader.ReadCounter(0); return v }
func (c *JavaTLSCollector) CounterRingbufDrops() uint64 { v, _ := c.loader.ReadCounter(1); return v }
func (c *JavaTLSCollector) CounterReadFailed() uint64  { v, _ := c.loader.ReadCounter(2); return v }
func (c *JavaTLSCollector) CounterBytes() uint64       { v, _ := c.loader.ReadCounter(3); return v }
func (c *JavaTLSCollector) CounterBadCmd() uint64      { v, _ := c.loader.ReadCounter(4); return v }
