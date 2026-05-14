// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"

	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
	"github.com/postmanlabs/postman-insights-agent/ebpf/goexec"
	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// GoTLSTarget describes a Go binary the agent wants to attach uprobes to.
type GoTLSTarget struct {
	PID        uint32
	BinaryPath string // /host/proc/<pid>/exe or equivalent
	GoVersion  string
}

// GoTLSCollector manages a single GoTLSLoader (one BPF program collection
// shared across all Go targets, since the collection itself is binary-
// independent — only attach points vary), plus per-target link.Link handles.
type GoTLSCollector struct {
	loader  *loader.GoTLSLoader
	reader  *events.Reader
	adapter *events.Adapter
	rawTap  bool

	mu    sync.Mutex
	links map[uint32][]link.Link // pid → uprobe handles
}

// NewGoTLSCollector loads the BPF gotls collection and constructs a reader
// + adapter pumping into the same `out` channel the libssl path uses.
//
// Returns ErrUnsupported on builds without insights_bpf (stub provides it).
func NewGoTLSCollector(
	maxCaptureBytes uint32,
	adapter *events.Adapter,
) (*GoTLSCollector, error) {
	return NewGoTLSCollectorWithRawTap(maxCaptureBytes, adapter, false)
}

// NewGoTLSCollectorWithRawTap is like NewGoTLSCollector but optionally dumps
// raw decoded bytes to stderr for debugging.
func NewGoTLSCollectorWithRawTap(
	maxCaptureBytes uint32,
	adapter *events.Adapter,
	rawTap bool,
) (*GoTLSCollector, error) {
	if adapter == nil {
		return nil, fmt.Errorf("ebpf: GoTLSCollector requires an Adapter")
	}
	l, err := loader.LoadGoTLS(maxCaptureBytes)
	if err != nil {
		return nil, err
	}
	r, err := events.NewReader(l.EventsMap(), 4096)
	if err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("ebpf: gotls ringbuf reader: %w", err)
	}
	return &GoTLSCollector{
		loader:  l,
		reader:  r,
		adapter: adapter,
		rawTap:  rawTap,
		links:   map[uint32][]link.Link{},
	}, nil
}

// Run reads events from the gotls ringbuf and feeds them into the shared
// adapter until ctx is cancelled.
func (c *GoTLSCollector) Run(ctx context.Context, monoEpoch time.Time) {
	readerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		if err := c.reader.Run(readerCtx); err != nil {
			printer.Errorf("ebpf: gotls reader stopped: %v\n", err)
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
				printer.Stderr.Infof("gotls-raw: pid=%d ssl_ctx=0x%x len=%d/%d dir=%d %s\n",
					ev.PID, ev.SSLCtx, ev.LenCaptured, ev.LenTotal, ev.Direction,
					printableSnippet(ev.Bytes()))
			}
			c.adapter.Feed(ev, monoEpoch)
		}
	}
}

// Attach inspects the Go binary at path and attaches uprobes for the
// crypto/tls write entry. Per-PID — Go binaries have different symbol
// offsets so we can't share a single attach point.
func (c *GoTLSCollector) Attach(t GoTLSTarget) error {
	// Light inspection to confirm this is a Go binary and (later) capture
	// the Go version for telemetry.
	info, _ := goexec.Inspect(t.BinaryPath, nil)

	exe, err := c.loader.OpenExecutable(t.BinaryPath)
	if err != nil {
		return fmt.Errorf("ebpf: gotls open %s: %w", t.BinaryPath, err)
	}

	// Let cilium/ebpf resolve the symbol. Go uses mangled names like
	// `crypto/tls.(*Conn).Write` which are valid ELF symbol-table strings
	// and the library handles the .text-segment file-offset conversion.
	sym := "crypto/tls.(*Conn).Write"
	lnk, err := exe.Uprobe(sym,
		c.loader.WriteProg(),
		&link.UprobeOptions{PID: int(t.PID)})
	if err != nil {
		return fmt.Errorf("ebpf: gotls attach %s pid=%d: %w", sym, t.PID, err)
	}
	c.mu.Lock()
	c.links[t.PID] = append(c.links[t.PID], lnk)
	c.mu.Unlock()
	goVer := ""
	if info != nil {
		goVer = info.GoVersion
	}
	printer.Debugf("ebpf: attached gotls write uprobe pid=%d binary=%s go=%s symbol=%s\n",
		t.PID, t.BinaryPath, goVer, sym)
	return nil
}

// Detach removes all uprobes for a PID.
func (c *GoTLSCollector) Detach(pid uint32) error {
	c.mu.Lock()
	lnks := c.links[pid]
	delete(c.links, pid)
	c.mu.Unlock()
	var firstErr error
	for _, l := range lnks {
		if err := l.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Close releases all probes and the BPF collection.
func (c *GoTLSCollector) Close() error {
	c.mu.Lock()
	pids := make([]uint32, 0, len(c.links))
	for p := range c.links {
		pids = append(pids, p)
	}
	c.mu.Unlock()
	for _, p := range pids {
		_ = c.Detach(p)
	}
	_ = c.reader.Close()
	return c.loader.Close()
}

// printableSnippet renders the first 80 bytes of a slice as a printable
// string, replacing non-printable bytes with '.'.
func printableSnippet(b []byte) string {
	n := len(b)
	if n > 80 {
		n = 80
	}
	var sb strings.Builder
	sb.WriteString(strconv.Quote(string(replaceNonPrintable(b[:n]))))
	if len(b) > 80 {
		sb.WriteString("...")
	}
	return sb.String()
}

func replaceNonPrintable(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 32 && c < 127 {
			out[i] = c
		} else if c == '\r' || c == '\n' || c == '\t' {
			out[i] = c
		} else {
			out[i] = '.'
		}
	}
	return out
}

// CounterEmitted / Dropped / ReadFailed / Bytes expose the BPF-side counters
// for diagnostic dumps.
func (c *GoTLSCollector) CounterEmitted() uint64 { v, _ := c.loader.ReadCounter(0); return v }
func (c *GoTLSCollector) CounterDropped() uint64 { v, _ := c.loader.ReadCounter(1); return v }
func (c *GoTLSCollector) CounterReadFailed() uint64 { v, _ := c.loader.ReadCounter(2); return v }
func (c *GoTLSCollector) CounterBytes() uint64    { v, _ := c.loader.ReadCounter(3); return v }

// AttachedPIDs returns the PIDs we have attached uprobes for. Used for tests
// and diagnostics.
func (c *GoTLSCollector) AttachedPIDs() []uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]uint32, 0, len(c.links))
	for p := range c.links {
		out = append(out, p)
	}
	return out
}
