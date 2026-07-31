// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

import (
	"golang.org/x/sys/unix"
)

// bpfClockID is the POSIX clock that bpf_ktime_get_ns() reads in
// ebpf/programs/libssl.bpf.c.
//
// This MUST stay in sync with the BPF side. bpf_ktime_get_ns() is
// CLOCK_MONOTONIC — it excludes time the system spent suspended. (The BOOTTIME
// equivalent is a different helper, bpf_ktime_get_boot_ns().)
//
// Getting this wrong silently corrupts every witness timestamp: monotonicNow()
// is used to derive a wall-clock epoch, so if it reads a clock that runs ahead
// of the one the kernel stamped events with, the epoch lands in the past and
// every event is back-dated by the difference. This previously read
// CLOCK_BOOTTIME, which back-dated witnesses by the host's cumulative suspend
// time — 30.5 h for one customer on a laptop-hosted cluster, which starved the
// model builder and left their UI empty.
const bpfClockID int32 = unix.CLOCK_MONOTONIC

// monotonicNow returns nanoseconds on the same clock bpf_ktime_get_ns() uses.
//
// We call this once at startup to compute a wall-clock epoch for converting
// BPF-side timestamps into Go time.Time values:
//
//	monoEpoch = time.Now().Add(-monotonicNow())
//	eventTime = monoEpoch.Add(event.TimestampNS)
//
// CLOCK_MONOTONIC is mandatory on Linux, so the error path is unreachable in
// practice. There is deliberately no fallback to another clock: a different
// clock is not a degraded reading, it is a wrong one.
func monotonicNow() int64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(bpfClockID, &ts); err != nil {
		return 0
	}
	return ts.Nano()
}
