// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
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
// Both clock readings are taken at effectively the same instant, so the result
// is a stable offset between the two clocks — it does not matter how early or
// late in startup this is called. Callers must treat a returned error as fatal
// to capture: without a valid epoch, every witness timestamp would be wrong.
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
