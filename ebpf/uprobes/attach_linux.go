// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package uprobes

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
// Subsequent calls for the same PID are no-ops. Static targets use per-PID
// attach; when path is /proc/<pid>/exe and probes fail to bind, rootPath is
// tried as a fallback inside container mount namespaces.
func (m *Manager) AttachLibSSL(pid uint32, path string, static bool) error {
	m.mu.Lock()
	if att, ok := m.attached[pid]; ok {
		// Process exited and the PID was recycled, or the target switched
		// libssl paths — drop stale links so discovery can re-attach.
		if procAlive(pid) && att.path == path {
			m.mu.Unlock()
			return nil
		}
		m.mu.Unlock()
		_ = m.Detach(pid)
		m.mu.Lock()
	}

	tryPaths := []string{path}
	if static {
		if alt := staticAlternatePath(path, pid); alt != "" && alt != path {
			tryPaths = append(tryPaths, alt)
		}
	}

	var lastErr error
	for _, p := range tryPaths {
		att, err := m.tryAttachLocked(pid, p, static)
		if err != nil {
			lastErr = err
			continue
		}
		if len(att.links) == 0 {
			lastErr = fmt.Errorf("uprobes: no SSL probes bound at %s", p)
			continue
		}
		m.attached[pid] = att
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("uprobes: attach pid=%d: no probes bound", pid)
}

func procAlive(pid uint32) bool {
	_, err := os.Stat(filepath.Join("/proc", fmt.Sprintf("%d", pid)))
	return err == nil
}

func staticRootFallbackPath(exePath string, pid uint32) string {
	if !strings.HasPrefix(exePath, "/proc/") || !strings.HasSuffix(exePath, "/exe") {
		return ""
	}
	target, err := os.Readlink(exePath)
	if err != nil || !strings.HasPrefix(target, "/") {
		return ""
	}
	rootPath := filepath.Join("/proc", fmt.Sprintf("%d", pid), "root", target)
	if st, err := os.Stat(rootPath); err == nil && !st.IsDir() {
		return rootPath
	}
	return ""
}

func staticAlternatePath(path string, pid uint32) string {
	if strings.Contains(path, "/root/") {
		return filepath.Join("/proc", fmt.Sprintf("%d", pid), "exe")
	}
	return staticRootFallbackPath(path, pid)
}

func (m *Manager) tryAttachLocked(pid uint32, path string, static bool) (*pidAttachment, error) {
	exe, err := link.OpenExecutable(path)
	if err != nil {
		return nil, fmt.Errorf("uprobes: open %s: %w", path, err)
	}

	att := &pidAttachment{path: path}
	opts := &link.UprobeOptions{PID: int(pid)}
	if err := m.attachProbesLocked(exe, opts, att, static); err != nil {
		for _, c := range att.links {
			_ = c.Close()
		}
		return nil, err
	}
	return att, nil
}

func (m *Manager) attachProbesLocked(exe *link.Executable, opts *link.UprobeOptions, att *pidAttachment, static bool) error {
	cleanup := func() {
		for _, c := range att.links {
			_ = c.Close()
		}
		att.links = nil
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
	if static {
		// Node's static BoringSSL build also exposes internal entrypoints.
		pairs = append(pairs,
			probePair{"ssl_read", rEnt, rExt},
			probePair{"ssl_write", wEnt, wExt},
		)
	}

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
			return fmt.Errorf("uprobes: attach %s: %w", s.symbol, err)
		}
		att.links = append(att.links, up)
	}

	for _, p := range pairs {
		up, err := exe.Uprobe(p.symbol, p.entry, opts)
		if err != nil {
			if errors.Is(err, link.ErrNoSymbol) {
				continue
			}
			cleanup()
			return fmt.Errorf("uprobes: attach uprobe %s: %w", p.symbol, err)
		}
		att.links = append(att.links, up)

		ret, err := exe.Uretprobe(p.symbol, p.exit, opts)
		if err != nil {
			cleanup()
			return fmt.Errorf("uprobes: attach uretprobe %s: %w", p.symbol, err)
		}
		att.links = append(att.links, ret)
	}

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
	return closeLinks(att.links)
}

func closeLinks(links []io.Closer) error {
	var firstErr error
	for _, c := range links {
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

// ProbeCount returns the number of uprobe links attached to pid.
func (m *Manager) ProbeCount(pid uint32) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if att, ok := m.attached[pid]; ok {
		return len(att.links)
	}
	return 0
}
