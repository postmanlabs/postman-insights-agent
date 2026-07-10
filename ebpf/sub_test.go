// SPDX-License-Identifier: Apache-2.0

package ebpf

import "testing"

// These tests exercise the pure routing decision (routeSub) with no BPF loader
// or kernel dependency, so they run on every platform via plain `go test`.

func TestRouteSub_NetnsMatchWins(t *testing.T) {
	byNetnsSub := &podSub{}
	byPIDSub := &podSub{}
	byNetns := map[uint64]*podSub{4026533959: byNetnsSub}
	byPID := map[uint32]*podSub{3146: byPIDSub}

	// netns matches -> route by netns, even though the (init-ns) pid would also
	// resolve via the fallback map. This is the KIND case: eventPID=4399 has no
	// entry, but the netns does.
	if got := routeSub(byNetns, byPID, 4026533959, 4399); got != byNetnsSub {
		t.Fatalf("expected netns subscriber %p, got %p", byNetnsSub, got)
	}
}

func TestRouteSub_PIDFallbackWhenNetnsZero(t *testing.T) {
	byPIDSub := &podSub{}
	byNetns := map[uint64]*podSub{4026533959: {}}
	byPID := map[uint32]*podSub{3146: byPIDSub}

	// netns inode unavailable (0) -> fall back to PID (non-nested node behaviour).
	if got := routeSub(byNetns, byPID, 0, 3146); got != byPIDSub {
		t.Fatalf("expected PID fallback subscriber %p, got %p", byPIDSub, got)
	}
}

func TestRouteSub_PIDFallbackWhenNetnsUnregistered(t *testing.T) {
	byPIDSub := &podSub{}
	byNetns := map[uint64]*podSub{4026533959: {}}
	byPID := map[uint32]*podSub{3146: byPIDSub}

	// A non-zero but unregistered netns falls back to PID rather than dropping.
	if got := routeSub(byNetns, byPID, 9999, 3146); got != byPIDSub {
		t.Fatalf("expected PID fallback subscriber %p, got %p", byPIDSub, got)
	}
}

func TestRouteSub_NoMatchReturnsNil(t *testing.T) {
	byNetns := map[uint64]*podSub{4026533959: {}}
	byPID := map[uint32]*podSub{3146: {}}

	// Neither netns nor pid registered -> nil (event is dropped).
	if got := routeSub(byNetns, byPID, 9999, 4399); got != nil {
		t.Fatalf("expected nil (drop), got %p", got)
	}
}
