// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

import (
	"strings"
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
//  2. The machine stops running AFTER the agent starts — guest suspend, a paused
//     VM (what a Mac lid-close does to Docker Desktop), or a wall-clock step.
//     MONOTONIC stalls while wall clock moves on, so a once-computed epoch
//     drifts. Fixed by adjustEpoch, and covered deterministically by
//     TestAdjustEpoch* below.
//
// BLIND SPOT for mode 1: on a host that has never suspended, CLOCK_MONOTONIC and
// CLOCK_BOOTTIME return identical values, so the runtime checks here cannot tell
// them apart and would have passed against the buggy code. CI runners, cloud VMs
// and fresh containers are all in that category — which is exactly why this bug
// reached a customer. The mode-2 tests do not share this weakness: they hand
// adjustEpoch a deliberately stale epoch rather than relying on the host having
// stopped running, so they discriminate on any machine.

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
			"%v (tolerance %v)", eventTime, skew, before, tolerance)
	}
}

// TestMonotonicEpochHasNoMonotonicReading guards a subtle trap that made
// adjustEpoch a silent no-op.
//
// time.Now() attaches a monotonic clock reading and Add preserves it. Sub uses the
// monotonic components whenever BOTH operands carry one, and Go's monotonic clock is
// CLOCK_MONOTONIC — the very clock the epoch is derived against. So a
// monotonic-carrying epoch makes adjustEpoch's drift cancel to exactly zero, hiding
// the wall-clock jump it exists to detect.
//
// TestAdjustEpochCorrectsBackDating cannot catch this: it fabricates a stale epoch
// with Add, which shifts the monotonic reading too, so the synthetic drift is visible
// via monotonic even when a real one would not be. Hence this separate check.
//
// String() is the documented way to observe the reading: it appends a final
// "m=±<value>" field when one is present.
func TestMonotonicEpochHasNoMonotonicReading(t *testing.T) {
	epoch, err := monotonicEpoch()
	if err != nil {
		t.Fatalf("monotonicEpoch() returned an error: %v", err)
	}

	if s := epoch.String(); strings.Contains(s, " m=") {
		t.Errorf("monotonicEpoch() carries a monotonic clock reading (%s); Sub would "+
			"then compare monotonic components and adjustEpoch would compute zero drift "+
			"forever. Strip it with Round(0).", s)
	}

	// Behavioural companion: a purely wall-clock shift must be visible through Sub.
	// With a monotonic reading present this difference would read as ~0.
	const shift = 6 * time.Hour
	if got := epoch.Add(-shift).Sub(epoch); got != -shift {
		t.Errorf("wall-clock shift of %v measured as %v through Sub; the epoch is not "+
			"a pure wall-clock value", -shift, got)
	}
}

// TestAdjustEpochCorrectsBackDating is the regression test for failure mode 2,
// and unlike the checks above it has full discriminating power on any host —
// including CI runners and Docker Desktop VMs that have never stopped running.
//
// The trick is to hand adjustEpoch an epoch that is 6 h too early. That is
// indistinguishable, from its point of view, from the machine having just resumed
// after 6 h of not running. Without the correction the epoch stays stale and every
// subsequent witness is back-dated by 6 h — precisely the reported bug.
func TestAdjustEpochCorrectsBackDating(t *testing.T) {
	correct, err := monotonicEpoch()
	if err != nil {
		t.Fatalf("monotonicEpoch() returned an error: %v", err)
	}

	const stopped = 6 * time.Hour
	stale := correct.Add(-stopped)

	got := adjustEpoch(stale)

	const tolerance = 100 * time.Millisecond
	if drift := got.Sub(correct); drift < -tolerance || drift > tolerance {
		t.Errorf("adjustEpoch left the epoch %v away from correct after a simulated %v "+
			"stall (tolerance %v); witnesses after a resume would be back-dated by that much",
			drift, stopped, tolerance)
	}

	// Guard the direction: a stale epoch must move forward, never further back.
	if !got.After(stale) {
		t.Errorf("epoch moved from %v to %v — it must move forward to catch up", stale, got)
	}
}

// TestAdjustEpochIgnoresNoise checks the common case: nothing has happened since
// the epoch was derived, so it must not move at all. If it drifted here, the epoch
// would be nudged on every GC tick and timestamps on a single flow could straddle a
// change, producing the negative processing latency that ebpf/events/adapter.go
// documents having already been fixed once.
func TestAdjustEpochIgnoresNoise(t *testing.T) {
	epoch, err := monotonicEpoch()
	if err != nil {
		t.Fatalf("monotonicEpoch() returned an error: %v", err)
	}

	if got := adjustEpoch(epoch); !got.Equal(epoch) {
		t.Errorf("epoch moved by %v with nothing to correct, want no change", got.Sub(epoch))
	}

	// Sub-threshold drift in either direction must also be left alone.
	for _, skew := range []time.Duration{500 * time.Millisecond, -500 * time.Millisecond} {
		nudged := epoch.Add(skew)
		if got := adjustEpoch(nudged); !got.Equal(nudged) {
			t.Errorf("epoch with %v sub-threshold skew was adjusted to %v, want no change",
				skew, got)
		}
	}
}
