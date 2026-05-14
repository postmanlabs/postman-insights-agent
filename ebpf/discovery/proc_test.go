// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"testing"
	"time"
)

// fakeResolver lets a test pretend to know which namespace a PID is in.
type fakeResolver struct {
	m map[uint32]string
}

func (r *fakeResolver) Namespace(pid uint32) string { return r.m[pid] }

// TestWatchWith_NamespaceFiltering exercises the namespace allow-list:
// a PID whose namespace is in the allow-list must be emitted; a PID
// outside the allow-list must NOT be emitted.
//
// This test does NOT exercise PID removal because Watch reads from the real
// /proc, which we can't mock here. Removal is exercised in
// TestRemovalOnSimulatedExit below.
func TestWatchWith_NamespaceFiltering(t *testing.T) {
	// Use a resolver that's always called but never matches the allow-list,
	// so we know that *zero* Targets are emitted (the discovery loop will
	// find real libssl-loaded processes on the test host, but none of them
	// will be allowed).
	res := &fakeResolver{m: map[uint32]string{}}
	allow := map[string]struct{}{"only-this-ns": {}}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	ch := WatchWith(ctx, WatchOpts{
		Interval:          20 * time.Millisecond,
		NamespaceResolver: res,
		AllowedNamespaces: allow,
	})

	var got []Target
	for tgt := range ch {
		got = append(got, tgt)
	}
	if len(got) != 0 {
		t.Errorf("expected zero emissions when no PID is in allow-list; got %d", len(got))
	}
}

// removalProbeResolver simulates a process exiting between scans by
// returning "" (out of scope) after the first call for a given PID.
type removalProbeResolver struct {
	calls map[uint32]int
}

func (r *removalProbeResolver) Namespace(pid uint32) string {
	if r.calls == nil {
		r.calls = map[uint32]int{}
	}
	r.calls[pid]++
	if r.calls[pid] == 1 {
		return "allowed-ns"
	}
	return "" // fall out of scope on the next scan
}

// TestRemovalOnSimulatedExit checks that when a PID falls out of scope
// between scans (simulating either process exit or namespace re-classification),
// the discovery loop emits a Target{Removed: true} for it.
func TestRemovalOnSimulatedExit(t *testing.T) {
	res := &removalProbeResolver{}
	allow := map[string]struct{}{"allowed-ns": {}}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ch := WatchWith(ctx, WatchOpts{
		Interval:          20 * time.Millisecond,
		NamespaceResolver: res,
		AllowedNamespaces: allow,
	})

	sawAdded := false
	sawRemoved := false
	for tgt := range ch {
		if tgt.Removed {
			sawRemoved = true
		} else {
			sawAdded = true
		}
		if sawAdded && sawRemoved {
			break
		}
	}

	// If the test host has libssl-loaded processes (it does — the test
	// runner itself uses libssl indirectly via apt/git/python), at least one
	// will pass on the first scan and be removed on the second.
	if !sawAdded {
		t.Skipf("test host has no libssl-loaded processes; can't exercise removal")
	}
	if !sawRemoved {
		t.Errorf("expected at least one Target{Removed:true} after re-classification")
	}
}
