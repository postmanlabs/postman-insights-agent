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
// corresponds to, for use with events.SSLEvent.Time.
//
// The value is only valid while the machine keeps running: see adjustEpoch,
// which callers must apply periodically to keep it honest.
//
// Callers must treat a returned error as fatal to capture: without a valid
// epoch, every witness timestamp would be wrong.
//
// The conversion lives here rather than at the call sites because getting the
// sign or the time.Duration wrapping wrong is precisely the failure this
// package has already shipped once.
func monotonicEpoch() (time.Time, error) {
	mono, err := monotonicNow()
	if err != nil {
		return time.Time{}, fmt.Errorf("unable to establish monotonic-clock epoch: %w", err)
	}
	return time.Now().Add(-time.Duration(mono)), nil
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

// epochDriftThreshold is the smallest epoch error we bother correcting.
//
// Re-deriving the epoch involves two separate syscalls, so a freshly computed
// value differs from a correct stored one by sub-microsecond noise (measured at
// ~2 µs on a Docker Desktop VM). One second sits six orders of magnitude above
// that noise, and far below any suspend or clock step worth reacting to. It also
// comfortably absorbs NTP *slew*, which is bounded to a few hundred ppm — about
// 7 ms over a 15 s tick.
const epochDriftThreshold = time.Second

// adjustEpoch re-derives the monotonic→wall-clock epoch and adopts the new value
// if it has drifted from the stored one by more than epochDriftThreshold.
//
// Why this is needed: the epoch maps CLOCK_MONOTONIC onto wall clock, but
// MONOTONIC stalls whenever the machine stops running while wall clock keeps
// advancing. Anything that does that leaves the epoch too early, back-dating
// every subsequent witness — the same failure as the original CLOCK_BOOTTIME
// bug, just triggered later. A laptop-hosted cluster (kind/k3d/minikube) hits
// this every time the lid closes.
//
// Comparing against wall clock, rather than tracking CLOCK_BOOTTIME - MONOTONIC,
// is deliberate. The BOOTTIME difference only reveals suspends the *guest kernel*
// accounted for. It misses a paused VM — which is what a Mac lid-close does to
// Docker Desktop, and what live-migration or a throttled hypervisor does in
// production — because both clocks stall together and their difference never
// changes. Checking the epoch itself catches guest suspend, VM pause and NTP
// steps alike, without needing to tell them apart.
//
// The threshold is what keeps this safe. Adopting a new epoch on every tick would
// nudge it continuously, so two timestamps on one flow could straddle a change and
// produce negative processing latency — see the msgStart comment in
// ebpf/events/adapter.go. Below the threshold the epoch is left exactly alone.
//
// Not goroutine-safe: callers must hold the epoch in a single goroutine (both
// Collect and NodeCollector.Run read and update it from one event loop).
func adjustEpoch(epoch time.Time) time.Time {
	fresh, err := monotonicEpoch()
	if err != nil {
		// Keep what we have; a stale epoch beats a corrupted one.
		printer.Debugf("ebpf: clock re-check failed (%v); leaving epoch unchanged\n", err)
		return epoch
	}

	drift := fresh.Sub(epoch)
	if drift > -epochDriftThreshold && drift < epochDriftThreshold {
		return epoch
	}

	suspendNote := ""
	if suspended, err := suspendedSinceBoot(); err == nil {
		suspendNote = fmt.Sprintf(", guest-accounted suspend since boot: %v", suspended)
	}
	printer.Infof("ebpf: clock epoch drifted by %v (host suspended, VM paused, or wall "+
		"clock stepped); adopting new epoch to keep witness timestamps on wall clock%s\n",
		drift, suspendNote)
	return fresh
}
