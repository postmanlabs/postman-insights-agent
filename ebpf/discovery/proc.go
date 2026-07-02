// Package discovery enumerates the processes that the eBPF subsystem should
// attach uprobes to.
//
// The discovery loop polls /proc, tracks PID liveness, and emits Target events
// for both newly-seen and exited processes so the uprobes Manager can attach
// and detach cleanly.
//
// Namespace filtering is applied via the optional KubeNamespaceResolver. When
// that resolver is nil (e.g. when running outside a kube cluster), namespace
// filtering is a no-op and all libssl-loaded PIDs are emitted.

package discovery

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/postmanlabs/postman-insights-agent/ebpf/uprobes"
)

// Target represents a discovery event: a process newly seen, or a process
// that disappeared. The receiver branches on Removed.
type Target struct {
	PID     uint32
	Lib     *uprobes.LibSSLPath // populated when Removed == false
	Seen    time.Time
	Removed bool // true → process has exited; uprobes should be detached
}

// NamespaceResolver returns the Kubernetes namespace for a PID, or "" if the
// PID isn't a kube pod (or kube integration is disabled). When set on
// Watch, the discovery loop filters PIDs to those whose namespace is in the
// AllowedNamespaces set.
type NamespaceResolver interface {
	Namespace(pid uint32) string
}

// WatchOpts customises the discovery loop.
type WatchOpts struct {
	// Interval between /proc scans. Default 2s when unset.
	Interval time.Duration

	// NamespaceResolver, when non-nil, is consulted for every candidate PID;
	// PIDs whose namespace is not in AllowedNamespaces are dropped. When nil,
	// all libssl-loaded PIDs are emitted.
	NamespaceResolver NamespaceResolver

	// AllowedNamespaces is the set of K8s namespaces whose PIDs are allowed
	// to be probed. Empty set with a non-nil NamespaceResolver means "no
	// namespaces allowed" (i.e. discovery emits nothing). Empty set with a
	// nil resolver means "no filtering" (every libssl-loaded PID is emitted).
	AllowedNamespaces map[string]struct{}

	// ProcRoot defaults to /proc. DaemonSet deployments pass /host/proc so
	// the PIDs we discover match BPF-emitted root-namespace PIDs.
	ProcRoot string

	// NetnsInodeFilter, when non-zero, restricts discovery to PIDs whose
	// /proc/<pid>/ns/net inode matches this value. This provides pod-level
	// precision: only processes inside the target container's network namespace
	// are emitted, regardless of what Kubernetes namespace they belong to.
	//
	// Takes priority over NamespaceResolver/AllowedNamespaces when non-zero.
	// Use this in the DaemonSet per-pod path to avoid N× duplicate captures
	// when a namespace has multiple pod replicas (horizontal scaling).
	NetnsInodeFilter uint64
}

// ScanProc walks /proc once and returns every PID that has a libssl mapping.
// Equivalent to ScanProcAt("/proc").
func ScanProc() ([]Target, error) { return ScanProcAt("/proc") }

// ScanProcAt walks the specified /proc mount and returns every PID that has
// a libssl mapping. Use /host/proc when running inside a DaemonSet so the
// scanned PIDs match BPF's root-namespace view.
func ScanProcAt(procRoot string) ([]Target, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("discovery: read %s: %w", procRoot, err)
	}

	var targets []Target
	now := time.Now()
	self := uint32(os.Getpid())

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
		if pid == self {
			continue
		}

		lib, err := uprobes.FindLibSSLAnyAt(procRoot, pid)
		if err != nil {
			continue
		}
		targets = append(targets, Target{PID: pid, Lib: lib, Seen: now})
	}

	return targets, nil
}

// Watch returns a channel of Target events. Polls /proc every
// opts.Interval and emits:
//
//   - One Target{Removed:false, Lib:...} the first time a PID is observed
//     with libssl mapped and (if a NamespaceResolver is set) whose namespace
//     is in AllowedNamespaces.
//   - One Target{Removed:true}          when a previously-emitted PID is
//     no longer visible in /proc OR its namespace falls out of scope.
//
// Callers consume the channel and attach/detach uprobes accordingly.
//
// Watch is a convenience wrapper around WatchWith that disables namespace
// filtering. Prefer WatchWith for production use with namespace scoping.
func Watch(ctx context.Context, interval time.Duration) <-chan Target {
	return WatchWith(ctx, WatchOpts{Interval: interval})
}

// pidNetnsInode returns the network-namespace inode for pid by stat-ing
// <procRoot>/<pid>/ns/net. Returns 0 on any error (treated as "no match").
func pidNetnsInode(procRoot string, pid uint32) uint64 {
	if procRoot == "" {
		procRoot = "/proc"
	}
	path := fmt.Sprintf("%s/%d/ns/net", procRoot, pid)
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0
	}
	return st.Ino
}

// WatchWith starts the discovery loop with full options. See Watch for a
// simpler variant without namespace filtering.
func WatchWith(ctx context.Context, opts WatchOpts) <-chan Target {
	if opts.Interval <= 0 {
		opts.Interval = 2 * time.Second
	}
	out := make(chan Target, 64)
	// seen[pid] = last successful Target we emitted for this pid (held so we
	// can recompute the namespace allow check on each scan).
	seen := make(map[uint32]Target)

	allowed := func(pid uint32) bool {
		// Pod-level filter: inode match takes priority over namespace resolver.
		// Eliminates N× duplicate captures for scaled (multi-replica) pods.
		if opts.NetnsInodeFilter != 0 {
			return pidNetnsInode(opts.ProcRoot, pid) == opts.NetnsInodeFilter
		}
		if opts.NamespaceResolver == nil {
			return true
		}
		ns := opts.NamespaceResolver.Namespace(pid)
		if ns == "" {
			// PID is not a kube pod (e.g. host process). Default to NOT
			// probing — production discovery only wants kube workloads in
			// scope. Use Watch (no resolver) to capture all PIDs.
			return false
		}
		_, ok := opts.AllowedNamespaces[ns]
		return ok
	}

	go func() {
		defer close(out)
		t := time.NewTicker(opts.Interval)
		defer t.Stop()

		scan := func() {
			ts, err := ScanProcAt(opts.ProcRoot)
			if err != nil {
				return
			}

			// Build a set of currently-visible PIDs that pass the filter.
			current := make(map[uint32]Target, len(ts))
			for _, tgt := range ts {
				if !allowed(tgt.PID) {
					continue
				}
				current[tgt.PID] = tgt
			}

			// Emit Added events for PIDs newly seen or newly in-scope.
			for pid, tgt := range current {
				if _, was := seen[pid]; was {
					continue
				}
				select {
				case out <- tgt:
					seen[pid] = tgt
				case <-ctx.Done():
					return
				}
			}

			// Emit Removed events for PIDs that disappeared or fell out of
			// the namespace filter.
			for pid := range seen {
				if _, still := current[pid]; still {
					continue
				}
				select {
				case out <- Target{PID: pid, Removed: true, Seen: time.Now()}:
					delete(seen, pid)
				case <-ctx.Done():
					return
				}
			}
		}

		scan() // immediate
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				scan()
			}
		}
	}()

	return out
}
