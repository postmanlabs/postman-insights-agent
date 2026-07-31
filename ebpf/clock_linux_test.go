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
// IMPORTANT BLIND SPOT: on a host that has never suspended, CLOCK_MONOTONIC and
// CLOCK_BOOTTIME return identical values, so the runtime checks below cannot
// tell the two apart and would have passed against the buggy code. CI runners,
// cloud VMs and fresh containers are all in that category — which is exactly why
// this bug reached a customer. TestBPFClockIDMatchesKtimeGetNS is the check that
// holds regardless of host state; the runtime tests log the suspend delta so a
// green run can be interpreted honestly.

// clockNano reads a POSIX clock and returns its value in nanoseconds.
func clockNano(t *testing.T, clockID int32) int64 {
	t.Helper()

	var ts unix.Timespec
	if err := unix.ClockGettime(clockID, &ts); err != nil {
		t.Fatalf("ClockGettime(%d) failed: %v", clockID, err)
	}
	return ts.Nano()
}

// suspendDelta returns CLOCK_BOOTTIME - CLOCK_MONOTONIC, i.e. how long this host
// has spent suspended. This is the exact magnitude by which the old code
// back-dated witnesses, and zero on a host that has never slept.
func suspendDelta(t *testing.T) time.Duration {
	t.Helper()

	// MONOTONIC first so the (tiny) inter-syscall gap biases the delta up, not
	// down — we would rather over-report the discriminating power of this host.
	mono := clockNano(t, unix.CLOCK_MONOTONIC)
	boot := clockNano(t, unix.CLOCK_BOOTTIME)
	return time.Duration(boot - mono)
}

// TestBPFClockIDMatchesKtimeGetNS pins the Go side to the clock the BPF side
// uses. This is the only check here that fails deterministically on every host,
// including ones that have never suspended, so it is the real regression guard.
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
	delta := suspendDelta(t)
	t.Logf("host suspend delta (BOOTTIME-MONOTONIC): %v", delta)

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
			"reading CLOCK_BOOTTIME", skew, tolerance, delta)
	}

	if delta < tolerance {
		t.Logf("NOTE: this host has never suspended (delta %v), so CLOCK_MONOTONIC "+
			"and CLOCK_BOOTTIME are indistinguishable here. This test passing does "+
			"NOT prove the clock choice is correct — see "+
			"TestBPFClockIDMatchesKtimeGetNS.", delta)
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
	delta := suspendDelta(t)

	// A real event stamped "right now" by the BPF program would carry this value.
	tsNS := clockNano(t, unix.CLOCK_MONOTONIC)

	before := time.Now()
	monoEpoch, err := monotonicEpoch()
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
			"%v (tolerance %v); host suspend delta is %v",
			eventTime, skew, before, tolerance, delta)
	}
}
