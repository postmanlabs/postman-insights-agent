// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
)

// Regression tests for the witness-timestamp clock skew bug.
//
// The BPF programs stamp events with bpf_ktime_get_ns() (CLOCK_MONOTONIC).
// monotonicNow() must read the same clock, because the two are combined to map
// BPF timestamps onto wall clock. It used to read CLOCK_BOOTTIME, which
// includes suspended time, so on any host that had slept every witness was
// back-dated by the cumulative suspend duration.
//
// There are two distinct failure modes, and they need different tests:
//
//  1. Suspend BEFORE the agent starts — the original bug. Fixed by reading the
//     right clock. Only TestBPFClockIDMatchesKtimeGetNS catches a regression
//     here on every host; see the blind-spot note below.
//  2. Suspend AFTER the agent starts — MONOTONIC stalls while wall clock moves,
//     so a once-computed epoch drifts. Fixed by adjustEpochForSuspend, and
//     covered deterministically by TestAdjustEpochForSuspend* below.
//
// BLIND SPOT for mode 1: on a host that has never suspended, CLOCK_MONOTONIC and
// CLOCK_BOOTTIME return identical values, so the runtime checks here cannot tell
// them apart and would have passed against the buggy code. CI runners, cloud VMs
// and fresh containers are all in that category — which is exactly why this bug
// reached a customer. The mode-2 tests do not share this weakness: they fake the
// previous suspend sample rather than relying on the host having slept.

// clockNano reads a POSIX clock and returns its value in nanoseconds.
func clockNano(t *testing.T, clockID int32) int64 {
	t.Helper()

	var ts unix.Timespec
	if err := unix.ClockGettime(clockID, &ts); err != nil {
		t.Fatalf("ClockGettime(%d) failed: %v", clockID, err)
	}
	return ts.Nano()
}

// TestBPFClockIDMatchesKtimeGetNS pins the Go side to the clock the BPF side
// uses. This is the only check here that fails deterministically on every host,
// including ones that have never suspended, so it is the real regression guard
// for failure mode 1.
//
// If bpf_ktime_get_ns() in ebpf/programs/libssl.bpf.c is ever swapped for
// bpf_ktime_get_boot_ns(), update bpfClockID to unix.CLOCK_BOOTTIME along with
// it — and change this test in the same commit, deliberately.
func TestBPFClockIDMatchesKtimeGetNS(t *testing.T) {
	if bpfClockID != unix.CLOCK_MONOTONIC {
		t.Fatalf("bpfClockID = %d, want CLOCK_MONOTONIC (%d): bpf_ktime_get_ns() is "+
			"CLOCK_MONOTONIC, and reading any other clock back-dates or forward-dates "+
			"every witness by the difference between them",
			bpfClockID, unix.CLOCK_MONOTONIC)
	}
}

// TestMonotonicNowReadsBPFClock checks that monotonicNow() actually tracks
// CLOCK_MONOTONIC at runtime, not merely that the constant is spelled right.
func TestMonotonicNowReadsBPFClock(t *testing.T) {
	suspended, err := suspendedSinceBoot()
	if err != nil {
		t.Fatalf("suspendedSinceBoot() failed: %v", err)
	}
	t.Logf("host suspend delta (BOOTTIME-MONOTONIC): %v", suspended)

	got, err := monotonicNow()
	if err != nil {
		t.Fatalf("monotonicNow() returned an error: %v", err)
	}
	if got <= 0 {
		t.Fatalf("monotonicNow() = %d, want a positive nanosecond count", got)
	}

	want := clockNano(t, unix.CLOCK_MONOTONIC)

	// Generous tolerance: these are two separate syscalls, and the failure we
	// care about is measured in hours, not milliseconds.
	const tolerance = 100 * time.Millisecond
	if skew := time.Duration(want - got); skew < -tolerance || skew > tolerance {
		t.Errorf("monotonicNow() is %v off CLOCK_MONOTONIC (tolerance %v); "+
			"host suspend delta is %v, which is the skew expected if this is "+
			"reading CLOCK_BOOTTIME", skew, tolerance, suspended)
	}

	if suspended < tolerance {
		t.Logf("NOTE: this host has never suspended (delta %v), so CLOCK_MONOTONIC "+
			"and CLOCK_BOOTTIME are indistinguishable here. This test passing does "+
			"NOT prove the clock choice is correct — see "+
			"TestBPFClockIDMatchesKtimeGetNS.", suspended)
	}
}

// TestMonotonicEpochConvertsToWallClock exercises the full production path:
// derive the epoch via monotonicEpoch(), feed a BPF-style timestamp through
// events.SSLEvent.Time(), and confirm the result is the present moment rather
// than some point in the past.
//
// This also guards the sign and the time.Duration conversion inside
// monotonicEpoch(), and would catch an epoch left at time.Now() (which maps
// events into the future by the host's uptime).
func TestMonotonicEpochConvertsToWallClock(t *testing.T) {
	// A real event stamped "right now" by the BPF program would carry this value.
	tsNS := clockNano(t, unix.CLOCK_MONOTONIC)

	before := time.Now()
	monoEpoch, _, err := monotonicEpoch()
	if err != nil {
		t.Fatalf("monotonicEpoch() returned an error: %v", err)
	}

	if !monoEpoch.Before(before) {
		t.Errorf("monotonicEpoch() = %v, which is not before now (%v); the epoch "+
			"must sit roughly one uptime in the past", monoEpoch, before)
	}

	ev := events.SSLEvent{TimestampNS: uint64(tsNS)}
	eventTime := ev.Time(monoEpoch)

	// Generous tolerance for scheduling noise between the reads above.
	const tolerance = 2 * time.Second
	if skew := before.Sub(eventTime); skew < -tolerance || skew > tolerance {
		t.Errorf("event stamped now resolved to %v, which is %v away from wall clock "+
			"%v (tolerance %v)", eventTime, skew, before, tolerance)
	}
}

// TestAdjustEpochForSuspendCorrectsBackDating is the regression test for failure
// mode 2, and unlike the checks above it has full discriminating power on any
// host — including CI runners that have never slept.
//
// The trick is to fake the *previous* sample rather than the clock: passing a
// lastSuspended value that is 6 h stale is indistinguishable, from
// adjustEpochForSuspend's point of view, from the host having just woken from a
// 6 h sleep. Without the correction the epoch stays put and every witness after
// a resume is back-dated by 6 h.
func TestAdjustEpochForSuspendCorrectsBackDating(t *testing.T) {
	epoch, suspended, err := monotonicEpoch()
	if err != nil {
		t.Fatalf("monotonicEpoch() returned an error: %v", err)
	}

	const slept = 6 * time.Hour
	stale := suspended - slept // as if we last sampled before a 6 h sleep

	got, gotSuspended := adjustEpochForSuspend(epoch, stale)

	const tolerance = 100 * time.Millisecond
	moved := got.Sub(epoch)
	if moved < slept-tolerance || moved > slept+tolerance {
		t.Errorf("epoch moved by %v after a simulated %v suspend, want %v (tolerance %v); "+
			"witnesses captured after a resume will be back-dated by the shortfall",
			moved, slept, slept, tolerance)
	}

	if gotSuspended < suspended-tolerance || gotSuspended > suspended+tolerance {
		t.Errorf("returned suspend sample = %v, want ~%v; a wrong sample makes the "+
			"next adjustment over- or under-correct", gotSuspended, suspended)
	}
}

// TestAdjustEpochForSuspendIgnoresNoise checks the common case: no suspend since
// the last sample, so the epoch must not move. If this drifted, the epoch would
// be nudged on every GC tick and timestamps on a single flow could straddle a
// change, producing the negative processing latency that ebpf/events/adapter.go
// documents having already been fixed once.
func TestAdjustEpochForSuspendIgnoresNoise(t *testing.T) {
	epoch, suspended, err := monotonicEpoch()
	if err != nil {
		t.Fatalf("monotonicEpoch() returned an error: %v", err)
	}

	got, _ := adjustEpochForSuspend(epoch, suspended)
	if !got.Equal(epoch) {
		t.Errorf("epoch moved by %v with no intervening suspend, want no change",
			got.Sub(epoch))
	}

	// A negative step should be impossible, but must never drag the epoch
	// backwards if it somehow occurs.
	got, _ = adjustEpochForSuspend(epoch, suspended+time.Hour)
	if !got.Equal(epoch) {
		t.Errorf("epoch moved by %v on a negative suspend step, want no change",
			got.Sub(epoch))
	}
}
