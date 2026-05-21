// SPDX-License-Identifier: Apache-2.0

package apidump

import "testing"

// fakeResolver is a tiny pidNamespaceLookup that records the last PID it
// was asked about and returns whatever the test wires up in `byPID`.
// Lets us assert both happy-path and the early-exit paths in
// newNamespaceResolverForCollector without depending on real K8s.
type fakeResolver struct {
	byPID  map[uint32]string
	lastIn uint32 // last PID Namespace() was called with
	calls  int
}

func (f *fakeResolver) Namespace(pid uint32) string {
	f.calls++
	f.lastIn = pid
	if f.byPID == nil {
		return ""
	}
	return f.byPID[pid]
}

func TestNamespaceResolverForCollector_HappyPath(t *testing.T) {
	f := &fakeResolver{byPID: map[uint32]string{1234: "team-payments"}}
	fn := newNamespaceResolverForCollector(f)
	if fn == nil {
		t.Fatal("newNamespaceResolverForCollector returned nil for non-nil resolver")
	}
	got := fn("ebpf-pid-1234")
	if got != "team-payments" {
		t.Errorf("got %q, want team-payments", got)
	}
	if f.calls != 1 {
		t.Errorf("Namespace() calls = %d, want 1", f.calls)
	}
	if f.lastIn != 1234 {
		t.Errorf("Namespace() received pid=%d, want 1234", f.lastIn)
	}
}

func TestNamespaceResolverForCollector_NonEbpfTagSkipped(t *testing.T) {
	// Pcap-captured witnesses have netInterface like "eth0" or "lo".
	// Those must NOT trigger a Namespace() call — they have no PID.
	f := &fakeResolver{byPID: map[uint32]string{1: "foo"}}
	fn := newNamespaceResolverForCollector(f)

	cases := []string{"eth0", "lo", "any0", "ebpf-pid-", "ebpf-pi", ""}
	for _, tag := range cases {
		got := fn(tag)
		if got != "" {
			t.Errorf("ifaceTag=%q: got %q, want \"\"", tag, got)
		}
	}
	if f.calls != 0 {
		t.Errorf("non-eBPF tags should not call Namespace(); got %d calls", f.calls)
	}
}

func TestNamespaceResolverForCollector_GarbagePIDSkipped(t *testing.T) {
	// "ebpf-pid-foo" is malformed (non-numeric) — must NOT call Namespace()
	// (passing garbage as a uint32 would surface as Namespace(0), which
	// would silently match PID 0 if it were ever in the table).
	f := &fakeResolver{byPID: map[uint32]string{0: "kernel"}}
	fn := newNamespaceResolverForCollector(f)
	got := fn("ebpf-pid-foo")
	if got != "" {
		t.Errorf("garbage PID: got %q, want \"\"", got)
	}
	if f.calls != 0 {
		t.Errorf("garbage PID should not call Namespace(); got %d", f.calls)
	}
}

func TestNamespaceResolverForCollector_LargePID(t *testing.T) {
	// Linux PID max is 4194304 (2^22) by default and 2^31-1 on big setups.
	// We parse as uint32, so anything up to 2^32-1 must work.
	f := &fakeResolver{byPID: map[uint32]string{4194303: "team-big"}}
	fn := newNamespaceResolverForCollector(f)
	got := fn("ebpf-pid-4194303")
	if got != "team-big" {
		t.Errorf("large PID: got %q, want team-big", got)
	}
}

func TestNamespaceResolverForCollector_OverflowPIDReturnsEmpty(t *testing.T) {
	// 2^33 doesn't fit in uint32 — must error in ParseUint and we return "".
	f := &fakeResolver{}
	fn := newNamespaceResolverForCollector(f)
	got := fn("ebpf-pid-8589934592")
	if got != "" {
		t.Errorf("overflow PID: got %q, want \"\"", got)
	}
	if f.calls != 0 {
		t.Errorf("overflow PID should not call Namespace(); got %d", f.calls)
	}
}

func TestNamespaceResolverForCollector_NilResolverReturnsNil(t *testing.T) {
	// Defensive: passing a nil resolver returns nil rather than a fn that
	// would panic at first call.
	fn := newNamespaceResolverForCollector(nil)
	if fn != nil {
		t.Errorf("nil resolver should produce nil fn, got non-nil")
	}
}

func TestNamespaceResolverForCollector_ResolverReturnsEmpty(t *testing.T) {
	// PID not yet in the resolver's table (race at pod startup) — the
	// resolver returns "" and we propagate that. Redactor's per-namespace
	// lookup will then fall back to the global default.
	f := &fakeResolver{byPID: map[uint32]string{}} // empty
	fn := newNamespaceResolverForCollector(f)
	got := fn("ebpf-pid-99999")
	if got != "" {
		t.Errorf("unknown PID: got %q, want \"\"", got)
	}
	if f.calls != 1 {
		t.Errorf("should still call Namespace() for the lookup; got %d", f.calls)
	}
}
