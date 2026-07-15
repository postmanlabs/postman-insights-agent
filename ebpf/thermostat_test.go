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

// TestDecideCap exercises the pure throttle/recover decision, including the
// cooldown gate and the min/max bounds.
func TestDecideCap(t *testing.T) {
	newT := func() *Thermostat {
		return &Thermostat{
			ceiling:       16384,
			HighWatermark: 50.0,
			LowWatermark:  25.0,
			HighWindow:    10 * time.Second,
			LowWindow:     30 * time.Second,
			MinCap:        64,
		}
	}

	cases := []struct {
		name       string
		cap        uint32
		inCooldown bool
		avgHigh    float64
		nHigh      int
		avgLow     float64
		nLow       int
		want       uint32
	}{
		{"throttle halves", 16384, false, 60, 10, 60, 30, 8192},
		{"throttle respects floor", 64, false, 90, 10, 90, 30, 64},
		{"recover doubles", 4096, false, 10, 10, 10, 30, 8192},
		{"recover respects ceiling", 16384, false, 5, 10, 5, 30, 16384},
		{"cooldown blocks throttle", 16384, true, 90, 10, 90, 30, 16384},
		{"cooldown blocks recover", 4096, true, 5, 10, 5, 30, 4096},
		{"partial high window no throttle", 16384, false, 90, 4, 90, 4, 16384},
		{"partial low window no recover", 4096, false, 5, 10, 5, 12, 4096},
		{"in-band no change", 8192, false, 40, 10, 40, 30, 8192},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			th := newT()
			got := th.decideCap(c.cap, c.inCooldown, c.avgHigh, c.nHigh, c.avgLow, c.nLow)
			if got != c.want {
				t.Errorf("decideCap(cap=%d cooldown=%v avgHigh=%.0f nHigh=%d avgLow=%.0f nLow=%d) = %d, want %d",
					c.cap, c.inCooldown, c.avgHigh, c.nHigh, c.avgLow, c.nLow, got, c.want)
			}
		})
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
