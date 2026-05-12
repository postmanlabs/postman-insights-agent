// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

import (
	"time"

	"golang.org/x/sys/unix"
)

// monotonicNow returns nanoseconds since boot, matching bpf_ktime_get_ns().
//
// We use this once at startup to compute a wall-clock epoch for converting
// BPF-side timestamps into Go time.Time values.
func monotonicNow() int64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		// Fall back to MONOTONIC, which differs from BOOTTIME only when the
		// system was suspended. Close enough for relative ordering.
		_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	}
	return ts.Nano()
}

var _ = time.Now // keep the time import if monotonicNow grows later
