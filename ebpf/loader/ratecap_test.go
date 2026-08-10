// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package loader

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

// lookupPerCPU is a helper that reads all per-CPU slots for a PID from
// PidRateBuckets (PERCPU_HASH) and returns the slice.
func lookupPerCPU(t *testing.T, l *Loader, pid uint32) []uint64 {
	t.Helper()
	nCPU, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("PossibleCPU: %v", err)
	}
	got := make([]uint64, nCPU)
	if err := l.libssl.PidRateBuckets.Lookup(&pid, &got); err != nil {
		t.Fatalf("Lookup bucket pid=%d: %v", pid, err)
	}
	return got
}

// TestRateCapKnob loads the BPF program, sets a rate cap, manually populates
// one bucket, reads it back across all CPU slots, and verifies deletion.
//
// Requires root (CAP_BPF + CAP_PERFMON).
func TestRateCapKnob(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	l, err := Load(Default())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer l.Close()

	if err := l.SetRateCapPerSec(5); err != nil {
		t.Fatalf("SetRateCapPerSec: %v", err)
	}

	const fakePID uint32 = 99999
	if err := l.RefillRateBucket(fakePID, 5); err != nil {
		t.Fatalf("RefillRateBucket: %v", err)
	}

	// PidRateBuckets is PERCPU_HASH — all CPU slots must be set to 5.
	for cpu, v := range lookupPerCPU(t, l, fakePID) {
		if v != 5 {
			t.Errorf("CPU %d: bucket = %d, want 5", cpu, v)
		}
	}

	// Delete and verify entry is gone.
	if err := l.DeleteRateBucket(fakePID); err != nil {
		t.Fatalf("DeleteRateBucket: %v", err)
	}
	nCPU, _ := ebpf.PossibleCPU()
	dummy := make([]uint64, nCPU)
	pid := fakePID
	if err := l.libssl.PidRateBuckets.Lookup(&pid, &dummy); err == nil {
		t.Errorf("bucket still present after Delete")
	}
}

// TestRateCapPercpuIsolation verifies that RefillRateBucket initialises every
// CPU slot to the requested token count. This is the key PERCPU_HASH property:
// each CPU owns its copy so no atomic operations are needed in BPF.
func TestRateCapPercpuIsolation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	l, err := Load(Default())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer l.Close()

	const fakePID uint32 = 12345
	const wantTokens uint64 = 10

	if err := l.RefillRateBucket(fakePID, wantTokens); err != nil {
		t.Fatalf("RefillRateBucket: %v", err)
	}

	for cpu, v := range lookupPerCPU(t, l, fakePID) {
		if v != wantTokens {
			t.Errorf("CPU %d: tokens = %d, want %d", cpu, v, wantTokens)
		}
	}
}

// TestRateCapDisabled verifies that when rate_cap_per_sec == 0 (default),
// no bucket entry is required — the BPF program allows all events through.
func TestRateCapDisabled(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	l, err := Load(Default())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer l.Close()

	// Rate cap is 0 by default — do NOT call SetRateCapPerSec.
	nCPU, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatalf("PossibleCPU: %v", err)
	}
	const fakePID uint32 = 77777
	pid := fakePID
	dummy := make([]uint64, nCPU)
	if err := l.libssl.PidRateBuckets.Lookup(&pid, &dummy); err == nil {
		t.Errorf("expected no bucket entry when rate cap is disabled, got one")
	}
}

// TestRateCapRefillOverwrite verifies that a second RefillRateBucket call
// overwrites all CPU slots with the new token count.
func TestRateCapRefillOverwrite(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	l, err := Load(Default())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer l.Close()

	const fakePID uint32 = 55555

	if err := l.RefillRateBucket(fakePID, 3); err != nil {
		t.Fatalf("RefillRateBucket(3): %v", err)
	}
	if err := l.RefillRateBucket(fakePID, 7); err != nil {
		t.Fatalf("RefillRateBucket(7): %v", err)
	}

	for cpu, v := range lookupPerCPU(t, l, fakePID) {
		if v != 7 {
			t.Errorf("CPU %d: tokens = %d, want 7 after overwrite", cpu, v)
		}
	}
}
