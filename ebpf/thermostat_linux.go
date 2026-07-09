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
// Algorithm (matches OBI/Pixie heuristics):
//
//   * Sample %CPU every 1s using /proc/self/stat (utime + stime).
//   * If a 10s rolling window averages > HighWatermark, halve max_capture_bytes
//     down to a floor of 64 bytes. Log every transition.
//   * If a 30s rolling window averages < LowWatermark, double back up to the
//     configured ceiling. Log every transition.
//   * Hard bound: never below 64, never above the user-configured ceiling.
//
// The thermostat keeps a snapshot of its current decision visible via
// CurrentCap() so telemetry can include it.
type Thermostat struct {
	loader  *loader.Loader
	ceiling uint32 // configured max (user-set --https-body-size-cap)

	HighWatermark float64 // %CPU above which we throttle (default 5.0)
	LowWatermark  float64 // %CPU below which we recover (default 3.0)
	HighWindow    time.Duration
	LowWindow     time.Duration
	MinCap        uint32 // never below this (default 64)

	currentCap atomic.Uint32 // exposed via CurrentCap()
	cpuPct     atomic.Uint64 // last-measured %CPU * 100 (so atomic fits in u64)
}

// NewThermostat builds a thermostat that controls the given loader. The
// caller should still load with a reasonable max_capture_bytes; the
// thermostat will leave the value alone unless usage moves outside the
// watermarks.
func NewThermostat(l *loader.Loader, ceiling uint32) *Thermostat {
	if ceiling == 0 {
		ceiling = 1024
	}
	t := &Thermostat{
		loader:        l,
		ceiling:       ceiling,
		HighWatermark: 5.0,
		LowWatermark:  3.0,
		HighWindow:    10 * time.Second,
		LowWindow:     30 * time.Second,
		MinCap:        64,
	}
	t.currentCap.Store(ceiling)
	return t
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
// window.
func (t *Thermostat) maybeAdjust(now time.Time, samples []sample) {
	// Compute rolling averages for both windows.
	avgHigh, nHigh := windowAvg(samples, now.Add(-t.HighWindow))
	avgLow, nLow := windowAvg(samples, now.Add(-t.LowWindow))

	cap := t.currentCap.Load()

	// Need a full window before acting.
	if nHigh >= int(t.HighWindow/time.Second) && avgHigh > t.HighWatermark {
		newCap := cap / 2
		if newCap < t.MinCap {
			newCap = t.MinCap
		}
		if newCap != cap {
			if err := t.loader.SetMaxCaptureBytes(newCap); err != nil {
				printer.Stderr.Warningf("ebpf: thermostat throttle SetMaxCaptureBytes(%d) failed: %v\n", newCap, err)
				return
			}
			printer.Stderr.Infof(
				"ebpf: thermostat throttling — %.1f%% CPU over %s exceeded %.1f%%; max_capture_bytes %d → %d\n",
				avgHigh, t.HighWindow, t.HighWatermark, cap, newCap)
			t.currentCap.Store(newCap)
			return
		}
	}

	if nLow >= int(t.LowWindow/time.Second) && avgLow < t.LowWatermark && cap < t.ceiling {
		newCap := cap * 2
		if newCap > t.ceiling {
			newCap = t.ceiling
		}
		if newCap != cap {
			if err := t.loader.SetMaxCaptureBytes(newCap); err != nil {
				printer.Stderr.Warningf("ebpf: thermostat recover SetMaxCaptureBytes(%d) failed: %v\n", newCap, err)
				return
			}
			printer.Stderr.Infof(
				"ebpf: thermostat recovering — %.1f%% CPU over %s below %.1f%%; max_capture_bytes %d → %d\n",
				avgLow, t.LowWindow, t.LowWatermark, cap, newCap)
			t.currentCap.Store(newCap)
		}
	}
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
