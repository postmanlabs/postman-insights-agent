// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package loader

import (
	"os"
	"testing"
)

// TestLoadLibssl is the Phase 1 §4 smoke test. It boots the loader, asserts
// that the verifier accepts the program, and exercises Close().
//
// Requires:
//   - Linux kernel >= 5.8 (ringbuf, etc.)
//   - root or CAP_BPF + CAP_PERFMON
//   - /sys/kernel/btf/vmlinux available
//
// Skipped on non-root runs so `go test ./...` stays green in CI without
// privileges.
func TestLoadLibssl(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF + CAP_PERFMON)")
	}

	l, err := Load(Default())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer func() {
		if err := l.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	if l.EventsMap() == nil {
		t.Fatal("EventsMap is nil")
	}
	if l.TargetPIDsMap() == nil {
		t.Fatal("TargetPIDsMap is nil")
	}

	// Spot-check the programs are present.
	if r, ret := l.SSLReadProgs(); r == nil || ret == nil {
		t.Fatal("SSLReadProgs returned nil program(s)")
	}
	if w, ret := l.SSLWriteProgs(); w == nil || ret == nil {
		t.Fatal("SSLWriteProgs returned nil program(s)")
	}
	if r, ret := l.SSLReadExProgs(); r == nil || ret == nil {
		t.Fatal("SSLReadExProgs returned nil program(s)")
	}
	if w, ret := l.SSLWriteExProgs(); w == nil || ret == nil {
		t.Fatal("SSLWriteExProgs returned nil program(s)")
	}
}
