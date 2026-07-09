// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

import (
	"testing"
	"time"
)

// TestReadSelfCPUJiffies smoke-tests the /proc/self/stat parser: ticks must be
// monotonically non-decreasing across two calls separated by a busy spin.
func TestReadSelfCPUJiffies(t *testing.T) {
	a, err := readSelfCPUJiffies()
	if err != nil {
		t.Fatalf("first read: %v", err)
	}

	// Burn some CPU so utime/stime advance.
	deadline := time.Now().Add(100 * time.Millisecond)
	n := uint64(0)
	for time.Now().Before(deadline) {
		n++
	}
	_ = n

	b, err := readSelfCPUJiffies()
	if err != nil {
		t.Fatalf("second read: %v", err)
	}
	if b < a {
		t.Errorf("jiffies went backwards: %d -> %d", a, b)
	}
}

// TestWindowAvg checks the windowed-average helper with synthetic samples.
func TestWindowAvg(t *testing.T) {
	now := time.Now()
	samples := []sample{
		{ts: now.Add(-15 * time.Second), pct: 100}, // outside both windows
		{ts: now.Add(-5 * time.Second), pct: 10},
		{ts: now.Add(-1 * time.Second), pct: 20},
	}

	avg10, n10 := windowAvg(samples, now.Add(-10*time.Second))
	if n10 != 2 {
		t.Errorf("expected 2 samples in 10s window, got %d", n10)
	}
	if avg10 != 15.0 {
		t.Errorf("expected avg 15.0, got %.2f", avg10)
	}

	avg20, n20 := windowAvg(samples, now.Add(-20*time.Second))
	if n20 != 3 {
		t.Errorf("expected 3 samples in 20s window, got %d", n20)
	}
	if avg20 != (100.0+10.0+20.0)/3.0 {
		t.Errorf("unexpected avg %.2f", avg20)
	}
}
