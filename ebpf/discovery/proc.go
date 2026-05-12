// Package discovery enumerates the processes that the eBPF subsystem should
// attach uprobes to.
//
// In Phase 1 spike mode this is just "all PIDs that have libssl mapped". In
// Phase 2 production mode this integrates with:
//   - integrations/cri_apis      → list containers on this node
//   - integrations/kube_apis     → filter by namespace / label
// to attach only to containers in opted-in namespaces.
//
// The output of this package is a stream of (PID, libssl-path) tuples
// consumed by ebpf/uprobes.Manager.AttachLibSSL.

package discovery

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/postmanlabs/postman-insights-agent/ebpf/uprobes"
)

// Target is a process we want to attach probes to, together with the resolved
// libssl path for that process.
type Target struct {
	PID  uint32
	Lib  *uprobes.LibSSLPath
	Seen time.Time
}

// ScanProc walks /proc once and returns every PID that has a libssl mapping.
// Useful for Phase 1 spike validation; production uses Watch (below) to track
// process lifecycle.
func ScanProc() ([]Target, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("discovery: read /proc: %w", err)
	}

	var targets []Target
	now := time.Now()

	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(ent.Name(), 10, 32)
		if err != nil {
			continue // not a pid dir
		}
		pid := uint32(pid64)

		// Skip our own PID — uprobing ourselves causes recursion.
		if pid == uint32(os.Getpid()) {
			continue
		}

		lib, err := uprobes.FindLibSSL(pid)
		if err != nil {
			continue
		}
		targets = append(targets, Target{PID: pid, Lib: lib, Seen: now})
	}

	return targets, nil
}

// Watch returns a channel of newly-discovered Targets. Polls /proc every
// `interval` and emits one Target per newly-seen PID that has libssl.
//
// PHASE 1 SCAFFOLD: simple polling. Phase 2 replaces this with an inotify
// watcher on /proc plus CRI events for container start/stop.
func Watch(ctx context.Context, interval time.Duration) <-chan Target {
	out := make(chan Target, 64)
	seen := make(map[uint32]struct{})

	go func() {
		defer close(out)
		t := time.NewTicker(interval)
		defer t.Stop()

		emit := func() {
			ts, err := ScanProc()
			if err != nil {
				return
			}
			for _, tgt := range ts {
				if _, ok := seen[tgt.PID]; ok {
					continue
				}
				seen[tgt.PID] = struct{}{}
				select {
				case out <- tgt:
				case <-ctx.Done():
					return
				}
			}
		}

		emit() // first scan immediately
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				emit()
			}
		}
	}()

	return out
}
