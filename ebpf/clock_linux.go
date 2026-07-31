// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"

	"github.com/postmanlabs/postman-insights-agent/printer"
)

// bpfClockID is the POSIX clock that bpf_ktime_get_ns() reads in
// ebpf/programs/libssl.bpf.c.
//
// This MUST stay in sync with the BPF side. bpf_ktime_get_ns() is
// CLOCK_MONOTONIC — it excludes time the system spent suspended. (The BOOTTIME
// equivalent is a different helper, bpf_ktime_get_boot_ns().)
//
// Getting this wrong silently corrupts every witness timestamp: the reading is
// used to derive a wall-clock epoch, so if it comes from a clock running ahead
// of the one the kernel stamped events with, the epoch lands in the past and
// every event is back-dated by the difference. This previously read
// CLOCK_BOOTTIME, which back-dated witnesses by the host's cumulative suspend
// time — 30.5 h for one customer on a laptop-hosted cluster, which starved the
// model builder and left their UI empty.
const bpfClockID int32 = unix.CLOCK_MONOTONIC

// monotonicNow returns the current reading of the clock bpf_ktime_get_ns()
// uses, in nanoseconds.
//
// CLOCK_MONOTONIC is mandatory on Linux, so an error here means something is
// badly wrong with the host. We surface it rather than substituting a value,
// because there is no safe default: returning zero would place the derived
// epoch at time.Now(), mapping every BPF timestamp into the *future* by the
// host's uptime — the same corruption this file exists to prevent, in the
// opposite direction.
func monotonicNow() (int64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(bpfClockID, &ts); err != nil {
		return 0, fmt.Errorf("failed to read clock id %d (CLOCK_MONOTONIC): %w", bpfClockID, err)
	}
	return ts.Nano(), nil
}

// monotonicEpoch returns the wall-clock instant that a BPF timestamp of zero
// corresponds to, for use with events.SSLEvent.Time, together with the amount
// of time the host has spent suspended so far. Callers must keep that second
// value and feed it back into adjustEpochForSuspend — see that function for why.
//
// Callers must treat a returned error as fatal to capture: without a valid
// epoch, every witness timestamp would be wrong.
//
// The conversion lives here rather than at the call sites because getting the
// sign or the time.Duration wrapping wrong is precisely the failure this
// package has already shipped once.
func monotonicEpoch() (time.Time, time.Duration, error) {
	mono, err := monotonicNow()
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("unable to establish monotonic-clock epoch: %w", err)
	}
	epoch := time.Now().Add(-time.Duration(mono))

	// Not fatal: if we cannot read BOOTTIME we simply lose suspend correction,
	// which is strictly better than refusing to capture.
	suspended, err := suspendedSinceBoot()
	if err != nil {
		printer.Debugf("ebpf: cannot read CLOCK_BOOTTIME (%v); suspend correction disabled\n", err)
		suspended = 0
	}
	return epoch, suspended, nil
}

// suspendedSinceBoot returns how long the host has spent suspended, as
// CLOCK_BOOTTIME - CLOCK_MONOTONIC. BOOTTIME counts suspended time, MONOTONIC
// does not, so their difference is exactly the total time spent asleep.
func suspendedSinceBoot() (time.Duration, error) {
	var mono, boot unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono); err != nil {
		return 0, fmt.Errorf("failed to read CLOCK_MONOTONIC: %w", err)
	}
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot); err != nil {
		return 0, fmt.Errorf("failed to read CLOCK_BOOTTIME: %w", err)
	}
	return time.Duration(boot.Nano() - mono.Nano()), nil
}

// suspendAdjustThreshold is the smallest suspend we bother correcting for. The
// two clock reads in suspendedSinceBoot are separate syscalls, so the measured
// difference carries sub-millisecond noise; one second is far above that noise
// and far below any real suspend.
const suspendAdjustThreshold = time.Second

// adjustEpochForSuspend corrects an epoch for any suspend that happened since
// lastSuspended was sampled, and returns the corrected epoch plus a fresh
// sample. Callers pass both values back in on the next call.
//
// Why this is needed: the epoch maps CLOCK_MONOTONIC onto wall clock, but
// MONOTONIC stalls while the host is suspended and wall clock does not. So a
// suspend after the epoch was taken leaves it too early by exactly the suspend
// duration, back-dating every subsequent witness — the same failure as the
// original CLOCK_BOOTTIME bug, just triggered later. A laptop-hosted cluster
// (kind/k3d/minikube) hits this every time the lid closes.
//
// The correction is exact rather than approximate: if the host slept for S, the
// suspend delta grows by exactly S and the epoch must move forward by exactly S.
//
// This deliberately does NOT re-derive the epoch from scratch on a timer.
// Re-deriving would nudge the epoch continuously, so two timestamps on one flow
// could straddle a change and produce negative processing latency — see the
// msgStart comment in ebpf/events/adapter.go. This only moves the epoch on a
// real suspend, which is rare and is already a discontinuity in wall time.
//
// Not goroutine-safe: callers must hold the epoch in a single goroutine (both
// Collect and NodeCollector.Run read and update it from one event loop).
func adjustEpochForSuspend(epoch time.Time, lastSuspended time.Duration) (time.Time, time.Duration) {
	suspended, err := suspendedSinceBoot()
	if err != nil {
		// Keep what we have; a stale epoch beats a corrupted one.
		printer.Debugf("ebpf: suspend check failed (%v); leaving clock epoch unchanged\n", err)
		return epoch, lastSuspended
	}

	// A negative step should be impossible (the delta is non-decreasing), but if
	// it happens, resample without touching the epoch.
	step := suspended - lastSuspended
	if step < suspendAdjustThreshold {
		return epoch, suspended
	}

	printer.Infof("ebpf: host suspended for %v; advancing clock epoch to keep witness "+
		"timestamps on wall clock (total suspended since boot: %v)\n", step, suspended)
	return epoch.Add(step), suspended
}
