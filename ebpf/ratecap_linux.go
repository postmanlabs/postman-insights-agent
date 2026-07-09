// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

import (
	"context"
	"time"

	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
	"github.com/postmanlabs/postman-insights-agent/ebpf/uprobes"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// rateCapRefiller runs the userspace side of sampling layer 2 (per-PID rate
// cap). Every refill interval (1s):
//
//   - For every currently-attached PID, set its bucket to `tokensPerSec`.
//   - For every bucket whose PID is no longer attached, remove it.
//
// This is a "fill" rather than "increment" pattern: the BPF probe takes one
// token per event; what's not consumed by the next refill is forgiven. That
// matches the spec's per-second cap semantics (no carry-over) and is simpler
// than maintaining a fractional rate.
//
// If tokensPerSec is 0, the refiller is a no-op (the BPF side also early-exits
// when rate_cap_per_sec == 0).
func rateCapRefiller(
	ctx context.Context,
	ldr *loader.Loader,
	mgr *uprobes.Manager,
	tokensPerSec uint32,
) {
	if tokensPerSec == 0 {
		return
	}
	if err := ldr.SetRateCapPerSec(tokensPerSec); err != nil {
		printer.Stderr.Warningf("ebpf: SetRateCapPerSec(%d) failed: %v; rate cap disabled\n", tokensPerSec, err)
		return
	}
	tokens := uint64(tokensPerSec)

	t := time.NewTicker(1 * time.Second)
	defer t.Stop()

	prev := map[uint32]struct{}{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cur := map[uint32]struct{}{}
			for _, pid := range mgr.AttachedPIDs() {
				cur[pid] = struct{}{}
				if err := ldr.RefillRateBucket(pid, tokens); err != nil {
					printer.Debugf("ebpf: RefillRateBucket pid=%d: %v\n", pid, err)
				}
			}
			// Garbage-collect buckets for PIDs no longer attached.
			for pid := range prev {
				if _, still := cur[pid]; !still {
					_ = ldr.DeleteRateBucket(pid)
				}
			}
			prev = cur
		}
	}
}
