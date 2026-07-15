// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// Thermostat is a closed-loop controller that watches the agent's own CPU
// usage and adjusts the BPF-side max_capture_bytes knob to keep cost bounded.
//
// Algorithm:
//
//   - Sample %CPU every 1s using /proc/self/stat (utime + stime). %CPU is
//     expressed relative to a SINGLE core: 100.0 == one full core busy, so on a
//     multi-core box the value can exceed 100. Watermarks are in these units.
//   - If a 10s rolling window averages > HighWatermark, halve max_capture_bytes
//     down to a floor of 64 bytes.
//   - If a 30s rolling window averages < LowWatermark, double back up to the
//     configured ceiling.
//   - Cooldown: after any adjustment, make no further adjustment for
//     AdjustCooldown (default = HighWindow). Without this the loop would halve
//     every tick — the reduced cap's CPU effect takes several seconds to appear
//     in the rolling average, so back-to-back halving overshoots straight to the
//     64-byte floor. The cooldown lets the loop observe the effect of each step.
//   - Hard bound: never below MinCap (64), never above the configured ceiling.
//
// Defaults are deliberately generous (High 50% / Low 25% of one core): the
// measured value is the agent's WHOLE-process CPU (parsing, uploads, k8s
// informers, pcap path — not just the eBPF copy), so a tight threshold throttles
// even when capture is cheap. Override at runtime with the env vars
// POSTMAN_INSIGHTS_HTTPS_CPU_HIGH_PCT / _LOW_PCT (percent of one core).
//
// The thermostat keeps a snapshot of its current decision visible via
// CurrentCap() so telemetry can include it.
type Thermostat struct {
	loader  *loader.Loader
	ceiling uint32 // configured max (user-set --https-body-size-cap)

	HighWatermark float64 // %CPU (of one core) above which we throttle (default 50.0)
	LowWatermark  float64 // %CPU (of one core) below which we recover (default 25.0)
	HighWindow    time.Duration
	LowWindow     time.Duration
	MinCap        uint32        // never below this (default 64)
	AdjustCooldown time.Duration // min gap between adjustments (default = HighWindow)

	lastAdjust time.Time     // wall time of the last cap change (cooldown gate)
	currentCap atomic.Uint32 // exposed via CurrentCap()
	cpuPct     atomic.Uint64 // last-measured %CPU * 100 (so atomic fits in u64)
}

// NewThermostat builds a thermostat that controls the given loader. The
// caller should still load with a reasonable max_capture_bytes; the
// thermostat will leave the value alone unless usage moves outside the
// watermarks.
func NewThermostat(l *loader.Loader, ceiling uint32) *Thermostat {
	if ceiling == 0 {
		ceiling = 16384
	}
	t := &Thermostat{
		loader:        l,
		ceiling:       ceiling,
		HighWatermark: 50.0, // 50% of one core (see type doc for scale/rationale)
		LowWatermark:  25.0, // 25% of one core
		HighWindow:    10 * time.Second,
		LowWindow:     30 * time.Second,
		MinCap:        64,
	}
	t.AdjustCooldown = t.HighWindow

	// Optional runtime overrides (percent of one core). Applied only if valid
	// and if they preserve Low < High; otherwise keep defaults.
	if v, ok := envPositiveFloat("POSTMAN_INSIGHTS_HTTPS_CPU_HIGH_PCT"); ok {
		t.HighWatermark = v
	}
	if v, ok := envPositiveFloat("POSTMAN_INSIGHTS_HTTPS_CPU_LOW_PCT"); ok {
		t.LowWatermark = v
	}
	if t.LowWatermark >= t.HighWatermark {
		printer.Stderr.Warningf(
			"ebpf: thermostat watermark override invalid (low %.1f >= high %.1f); using defaults 25/50\n",
			t.LowWatermark, t.HighWatermark)
		t.HighWatermark, t.LowWatermark = 50.0, 25.0
	}

	t.currentCap.Store(ceiling)
	return t
}

// envPositiveFloat reads a strictly-positive float from an env var. Returns
// (0, false) when unset, unparseable, or <= 0.
func envPositiveFloat(key string) (float64, bool) {
	s := os.Getenv(key)
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v <= 0 {
		return 0, false
	}
	return v, true
}

// CurrentCap reports the most recent BPF-side max_capture_bytes the
// thermostat has set.
func (t *Thermostat) CurrentCap() uint32 { return t.currentCap.Load() }

// CPUPercent reports the most recent %CPU measurement (process-level,
// across all cores; e.g. 250.0 means 2.5 cores worth).
func (t *Thermostat) CPUPercent() float64 {
	return float64(t.cpuPct.Load()) / 100.0
}

// Run blocks until ctx is cancelled, sampling CPU every 1s and adjusting
// the BPF knob via Variable.Set.
func (t *Thermostat) Run(ctx context.Context) {
	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()

	// Ring buffer of recent samples sized for the longer of HighWindow /
	// LowWindow (type `sample` declared at file scope).
	windowCap := int(t.LowWindow/time.Second) + 4
	if windowCap < 32 {
		windowCap = 32
	}
	samples := make([]sample, 0, windowCap)

	var (
		lastCPU  uint64 // last total CPU jiffies (utime+stime)
		lastWall time.Time
	)

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			cpu, err := readSelfCPUJiffies()
			if err != nil {
				continue // transient; try again next tick
			}
			if !lastWall.IsZero() {
				wallDelta := now.Sub(lastWall).Seconds()
				cpuDelta := float64(cpu-lastCPU) / float64(clockTicksPerSecond())
				if wallDelta > 0 {
					pct := (cpuDelta / wallDelta) * 100.0
					t.cpuPct.Store(uint64(pct * 100))

					samples = append(samples, sample{ts: now, pct: pct})
					if len(samples) > windowCap {
						samples = samples[len(samples)-windowCap:]
					}

					t.maybeAdjust(now, samples)
				}
			}
			lastCPU = cpu
			lastWall = now
		}
	}
}

// maybeAdjust applies the throttle / recover decisions based on the samples
// window, honouring the post-adjustment cooldown. Runs in the single Run
// goroutine, so lastAdjust needs no locking.
func (t *Thermostat) maybeAdjust(now time.Time, samples []sample) {
	avgHigh, nHigh := windowAvg(samples, now.Add(-t.HighWindow))
	avgLow, nLow := windowAvg(samples, now.Add(-t.LowWindow))

	cap := t.currentCap.Load()
	inCooldown := !t.lastAdjust.IsZero() && now.Sub(t.lastAdjust) < t.AdjustCooldown

	newCap := t.decideCap(cap, inCooldown, avgHigh, nHigh, avgLow, nLow)
	if newCap == cap {
		return
	}

	verb := "throttling"
	avg, window, watermark := avgHigh, t.HighWindow, t.HighWatermark
	if newCap > cap {
		verb, avg, window, watermark = "recovering", avgLow, t.LowWindow, t.LowWatermark
	}
	if err := t.loader.SetMaxCaptureBytes(newCap); err != nil {
		printer.Stderr.Warningf("ebpf: thermostat %s SetMaxCaptureBytes(%d) failed: %v\n", verb, newCap, err)
		return
	}
	printer.Stderr.Infof(
		"ebpf: thermostat %s — %.1f%% CPU (of one core) over %s vs watermark %.1f%%; max_capture_bytes %d → %d\n",
		verb, avg, window, watermark, cap, newCap)
	t.currentCap.Store(newCap)
	t.lastAdjust = now
}

// decideCap is the pure throttle/recover decision: given the current cap, the
// cooldown state, and the rolling averages + sample counts for each window, it
// returns the next cap (== cap when no change). No I/O, so it is unit-testable.
func (t *Thermostat) decideCap(cap uint32, inCooldown bool, avgHigh float64, nHigh int, avgLow float64, nLow int) uint32 {
	if inCooldown {
		return cap
	}
	// Throttle: full high-window of samples averaging over the high watermark.
	if nHigh >= int(t.HighWindow/time.Second) && avgHigh > t.HighWatermark {
		newCap := cap / 2
		if newCap < t.MinCap {
			newCap = t.MinCap
		}
		return newCap
	}
	// Recover: full low-window averaging under the low watermark, room to grow.
	if nLow >= int(t.LowWindow/time.Second) && avgLow < t.LowWatermark && cap < t.ceiling {
		newCap := cap * 2
		if newCap > t.ceiling {
			newCap = t.ceiling
		}
		return newCap
	}
	return cap
}

func windowAvg(samples []sample, since time.Time) (float64, int) {
	var sum float64
	var n int
	for _, s := range samples {
		if s.ts.Before(since) {
			continue
		}
		sum += s.pct
		n++
	}
	if n == 0 {
		return 0, 0
	}
	return sum / float64(n), n
}

// sample is the per-tick record.
type sample struct {
	ts  time.Time
	pct float64
}

// readSelfCPUJiffies returns the process's cumulative CPU jiffies (utime + stime).
func readSelfCPUJiffies() (uint64, error) {
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, err
	}
	// Fields: pid (comm) state ppid pgrp session tty_nr tpgid flags
	//         minflt cminflt majflt cmajflt utime stime ...
	// comm may contain spaces, so split after the last ')'.
	s := string(b)
	rp := strings.LastIndex(s, ")")
	if rp < 0 {
		return 0, fmt.Errorf("malformed /proc/self/stat")
	}
	fields := strings.Fields(s[rp+1:])
	if len(fields) < 13 {
		return 0, fmt.Errorf("/proc/self/stat: not enough fields")
	}
	utime, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0, err
	}
	stime, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return 0, err
	}
	return utime + stime, nil
}

// clockTicksPerSecond returns sysconf(_SC_CLK_TCK) — typically 100 on Linux.
// Hardcoded because cgo is undesirable and the value is stable on production
// kernels.
func clockTicksPerSecond() uint64 { return 100 }
