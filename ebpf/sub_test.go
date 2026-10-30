package ebpf

import "testing"

// These tests exercise the pure routing decision (routeSub) with no BPF loader
// or kernel dependency, so they run on every platform via plain `go test`.

func TestRouteSub_NetnsMatchWins(t *testing.T) {
	byNetnsSub := &podSub{}
	byPIDSub := &podSub{}
	byNetns := routeTable[uint64]{4026533959: {byNetnsSub}}
	byPID := routeTable[uint32]{3146: {byPIDSub}}

	// netns matches -> route by netns, even though the (init-ns) pid would also
	// resolve via the fallback map. This is the KIND case: eventPID=4399 has no
	// entry, but the netns does.
	if got := routeSub(byNetns, byPID, 4026533959, 4399); got != byNetnsSub {
		t.Fatalf("expected netns subscriber %p, got %p", byNetnsSub, got)
	}
}

func TestRouteSub_PIDFallbackWhenNetnsZero(t *testing.T) {
	byPIDSub := &podSub{}
	byNetns := routeTable[uint64]{4026533959: {{}}}
	byPID := routeTable[uint32]{3146: {byPIDSub}}

	// netns inode unavailable (0) -> fall back to PID (non-nested node behaviour).
	if got := routeSub(byNetns, byPID, 0, 3146); got != byPIDSub {
		t.Fatalf("expected PID fallback subscriber %p, got %p", byPIDSub, got)
	}
}

func TestRouteSub_PIDFallbackWhenNetnsUnregistered(t *testing.T) {
	byPIDSub := &podSub{}
	byNetns := routeTable[uint64]{4026533959: {{}}}
	byPID := routeTable[uint32]{3146: {byPIDSub}}

	// A non-zero but unregistered netns falls back to PID rather than dropping.
	if got := routeSub(byNetns, byPID, 9999, 3146); got != byPIDSub {
		t.Fatalf("expected PID fallback subscriber %p, got %p", byPIDSub, got)
	}
}

func TestRouteSub_NoMatchReturnsNil(t *testing.T) {
	byNetns := routeTable[uint64]{4026533959: {{}}}
	byPID := routeTable[uint32]{3146: {{}}}

	// Neither netns nor pid registered -> nil (event is dropped).
	if got := routeSub(byNetns, byPID, 9999, 4399); got != nil {
		t.Fatalf("expected nil (drop), got %p", got)
	}
}

// hostNetwork pods share the node's netns: the PID picks the pod that
// registered it, and only among the subscribers of that netns.
func TestRouteSub_SharedNetnsPrefersPID(t *testing.T) {
	older, newer, elsewhere := &podSub{}, &podSub{}, &podSub{}
	byNetns := routeTable[uint64]{7: {older, newer}, 8: {elsewhere}}
	byPID := routeTable[uint32]{100: {older}, 200: {newer}, 300: {elsewhere}}

	for _, tc := range []struct {
		name string
		pid  uint32
		want *podSub
	}{
		{"the older pod's PID", 100, older},
		{"the newer pod's PID", 200, newer},
		{"an unregistered PID goes to the newest", 999, newer},
		{"a PID of another netns's pod goes to the newest", 300, newer},
	} {
		if got := routeSub(byNetns, byPID, 7, tc.pid); got != tc.want {
			t.Errorf("%s: routed to %p, want %p", tc.name, got, tc.want)
		}
	}
}

// Two subscriptions on one netns (hostNetwork pods, or a capture restarting
// before the old subscription's cleanup ran): whichever leaves first, the other
// keeps receiving events.
func TestRouteTable_SharedKeySurvivesEitherOrder(t *testing.T) {
	for _, firstLeaves := range []string{"older", "newer"} {
		t.Run(firstLeaves+" leaves first", func(t *testing.T) {
			older, newer := &podSub{}, &podSub{}
			r := routeTable[uint64]{}
			r.add(7, older)
			r.add(7, newer)
			if got := r.get(7); got != newer {
				t.Fatalf("events go to %p, want the newest %p", got, newer)
			}

			leaving, staying := older, newer
			if firstLeaves == "newer" {
				leaving, staying = newer, older
			}
			r.remove(7, leaving)
			if got := r.get(7); got != staying {
				t.Fatalf("after one left, events go to %p, want %p", got, staying)
			}
			r.remove(7, staying)
			if got := r.get(7); got != nil || len(r) != 0 {
				t.Fatalf("after both left: get=%p, %d keys left", got, len(r))
			}
		})
	}
}

func TestRouteTable_AddIsIdempotentAndRemoveUnknownIsSafe(t *testing.T) {
	s, other := &podSub{}, &podSub{}
	r := routeTable[uint32]{}
	r.add(1, s)
	r.add(1, s)
	if len(r[1]) != 1 {
		t.Fatalf("%d entries after adding the same subscriber twice", len(r[1]))
	}
	r.remove(1, other) // never added
	r.remove(2, s)     // unknown key
	if r.get(1) != s || len(r) != 1 {
		t.Fatal("removing an unknown subscriber changed the table")
	}
}
