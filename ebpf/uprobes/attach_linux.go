// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package uprobes

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
)

// Manager tracks attached uprobes per PID and detaches them on demand.
type Manager struct {
	loader *loader.Loader

	mu       sync.Mutex
	attached map[uint32]*pidAttachment
}

type pidAttachment struct {
	path string
	// One io.Closer per attached probe (8: 4 entry + 4 return).
	links []io.Closer
}

// NewManager wires a Manager to a loader that already has libssl programs
// loaded (loader.Load() returned successfully).
func NewManager(l *loader.Loader) *Manager {
	return &Manager{
		loader:   l,
		attached: make(map[uint32]*pidAttachment),
	}
}

// AttachLibSSL opens the binary at path and attaches all four uprobe pairs
// (read, read_ex, write, write_ex) for the given PID. If a probe symbol is
// missing (e.g. older OpenSSL without *_ex variants), it is silently skipped.
//
// Subsequent calls for the same PID are no-ops.
func (m *Manager) AttachLibSSL(pid uint32, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.attached[pid]; ok {
		return nil
	}

	exe, err := link.OpenExecutable(path)
	if err != nil {
		return fmt.Errorf("uprobes: open %s: %w", path, err)
	}

	att := &pidAttachment{path: path}
	cleanup := func() {
		for _, c := range att.links {
			_ = c.Close()
		}
	}

	type probePair struct {
		symbol string
		entry  *ebpf.Program
		exit   *ebpf.Program
	}

	rEnt, rExt := m.loader.SSLReadProgs()
	rxEnt, rxExt := m.loader.SSLReadExProgs()
	wEnt, wExt := m.loader.SSLWriteProgs()
	wxEnt, wxExt := m.loader.SSLWriteExProgs()
	setFD := m.loader.SSLSetFDProg()
	sslFree := m.loader.SSLFreeProg()

	pairs := []probePair{
		{"SSL_read", rEnt, rExt},
		{"SSL_read_ex", rxEnt, rxExt},
		{"SSL_write", wEnt, wExt},
		{"SSL_write_ex", wxEnt, wxExt},
	}

	opts := &link.UprobeOptions{PID: int(pid)}

	// Single-shot uprobes (no exit probe) for fd-tracking helpers.
	singles := []struct {
		symbol string
		prog   *ebpf.Program
	}{
		{"SSL_set_fd", setFD},
		{"SSL_free", sslFree},
	}
	for _, s := range singles {
		up, err := exe.Uprobe(s.symbol, s.prog, opts)
		if err != nil {
			if errors.Is(err, link.ErrNoSymbol) {
				continue
			}
			cleanup()
			return fmt.Errorf("uprobes: attach %s pid=%d: %w", s.symbol, pid, err)
		}
		att.links = append(att.links, up)
	}

	for _, p := range pairs {
		up, err := exe.Uprobe(p.symbol, p.entry, opts)
		if err != nil {
			// Missing symbol is non-fatal — older OpenSSL didn't have *_ex.
			if errors.Is(err, link.ErrNoSymbol) {
				continue
			}
			cleanup()
			return fmt.Errorf("uprobes: attach uprobe %s pid=%d: %w", p.symbol, pid, err)
		}
		att.links = append(att.links, up)

		ret, err := exe.Uretprobe(p.symbol, p.exit, opts)
		if err != nil {
			cleanup()
			return fmt.Errorf("uprobes: attach uretprobe %s pid=%d: %w", p.symbol, pid, err)
		}
		att.links = append(att.links, ret)
	}

	m.attached[pid] = att
	return nil
}

// Detach closes all uprobes attached to the given PID. Safe to call multiple
// times.
func (m *Manager) Detach(pid uint32) error {
	m.mu.Lock()
	att, ok := m.attached[pid]
	delete(m.attached, pid)
	m.mu.Unlock()

	if !ok {
		return nil
	}
	var firstErr error
	for _, c := range att.links {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Close detaches every probe owned by this manager.
func (m *Manager) Close() error {
	m.mu.Lock()
	pids := make([]uint32, 0, len(m.attached))
	for pid := range m.attached {
		pids = append(pids, pid)
	}
	m.mu.Unlock()

	var firstErr error
	for _, pid := range pids {
		if err := m.Detach(pid); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// AttachedPIDs returns the PIDs currently being traced. Used for telemetry.
func (m *Manager) AttachedPIDs() []uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]uint32, 0, len(m.attached))
	for pid := range m.attached {
		out = append(out, pid)
	}
	return out
}
