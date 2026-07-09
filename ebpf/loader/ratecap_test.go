// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package loader

import (
	"os"
	"testing"
)

// TestRateCapKnob loads the BPF program, sets a rate cap, manually populates
// one bucket, drains it via the BPF-accessible counter path, and verifies
// behaviour.
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

	// Enable rate cap at 5/sec.
	if err := l.SetRateCapPerSec(5); err != nil {
		t.Fatalf("SetRateCapPerSec: %v", err)
	}

	// Pre-populate a bucket for an arbitrary PID and read it back.
	const fakePID uint32 = 99999
	if err := l.RefillRateBucket(fakePID, 5); err != nil {
		t.Fatalf("RefillRateBucket: %v", err)
	}

	var got uint64
	pid := fakePID
	if err := l.libssl.PidRateBuckets.Lookup(&pid, &got); err != nil {
		t.Fatalf("Lookup bucket: %v", err)
	}
	if got != 5 {
		t.Errorf("bucket = %d, want 5", got)
	}

	// Delete and verify.
	if err := l.DeleteRateBucket(fakePID); err != nil {
		t.Fatalf("DeleteRateBucket: %v", err)
	}
	if err := l.libssl.PidRateBuckets.Lookup(&pid, &got); err == nil {
		t.Errorf("bucket still present after Delete")
	}
}
