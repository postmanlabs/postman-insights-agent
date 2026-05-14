// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

import (
	"context"
	"fmt"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"

	"github.com/postmanlabs/postman-insights-agent/ebpf/discovery"
	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
	"github.com/postmanlabs/postman-insights-agent/ebpf/uprobes"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// Args bundles configuration for Collect.
type Args struct {
	// MaxCaptureBytes is the per-event plaintext byte cap (forwarded to BPF).
	MaxCaptureBytes uint32

	// EnforcePIDAllowlist gates whether the BPF probe ignores PIDs that
	// aren't in the target_pids map. Phase 1 spike defaults to false; Phase 2
	// production defaults to true.
	EnforcePIDAllowlist bool

	// DiscoveryInterval controls how often we re-scan /proc for new PIDs
	// that have libssl loaded. Phase 2 will replace polling with events.
	DiscoveryInterval time.Duration

	// FlowIdleTimeout governs how long we keep per-flow parser state after
	// the last byte was observed.
	FlowIdleTimeout time.Duration

	// FactorySelector is the akinet TCP parser factory selector. Callers
	// pass the same selector the pcap path uses, so this subsystem emits
	// the same akinet types into the same downstream pipeline.
	FactorySelector akinet.TCPParserFactorySelector

	// Out is where parsed HTTP requests and responses are pushed.
	Out chan<- akinet.ParsedNetworkTraffic
}

// Defaults returns the default Args for Phase 1 spike mode.
func Defaults() Args {
	return Args{
		MaxCaptureBytes:     1024,
		EnforcePIDAllowlist: false,
		DiscoveryInterval:   5 * time.Second,
		FlowIdleTimeout:     30 * time.Second,
	}
}

// Collect runs the eBPF HTTPS capture pipeline until ctx is cancelled.
//
// Returns ErrUnsupported on platforms / builds without eBPF.
func Collect(ctx context.Context, args Args) error {
	if args.Out == nil {
		return fmt.Errorf("ebpf: Args.Out is nil")
	}
	if args.FactorySelector == nil {
		return fmt.Errorf("ebpf: Args.FactorySelector is nil")
	}

	// 1. Load BPF programs.
	l, err := loader.Load(loader.Config{
		EnforcePIDAllowlist: args.EnforcePIDAllowlist,
		MaxCaptureBytes:     args.MaxCaptureBytes,
	})
	if err != nil {
		return fmt.Errorf("ebpf: load: %w", err)
	}
	defer func() { _ = l.Close() }()

	// 2. Start ring-buffer reader.
	reader, err := events.NewReader(l.EventsMap(), 4096)
	if err != nil {
		return fmt.Errorf("ebpf: new reader: %w", err)
	}
	defer func() { _ = reader.Close() }()

	readerCtx, cancelReader := context.WithCancel(ctx)
	defer cancelReader()
	go func() {
		if err := reader.Run(readerCtx); err != nil {
			printer.Errorf("ebpf: reader stopped: %v\n", err)
		}
	}()

	// 3. Construct adapter; feed events into akinet parsers → args.Out.
	adapter := events.NewAdapter(args.FactorySelector, args.Out)

	// 4. Start uprobe manager + process discovery.
	mgr := uprobes.NewManager(l)
	defer func() { _ = mgr.Close() }()

	disco := discovery.Watch(ctx, args.DiscoveryInterval)

	// Establish monotonic-clock epoch so event timestamps map to wall clock.
	monoEpoch := time.Now().Add(-time.Duration(monotonicNow()))

	// 5. Main loop: route discovered targets to the uprobe manager, route
	//    BPF events to the adapter, periodically GC stale flows.
	gcTicker := time.NewTicker(args.FlowIdleTimeout / 2)
	defer gcTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil

		case tgt, ok := <-disco:
			if !ok {
				disco = nil
				continue
			}
			if tgt.Removed {
				if err := mgr.Detach(tgt.PID); err != nil {
					printer.Debugf("ebpf: detach pid=%d failed: %v\n", tgt.PID, err)
				} else {
					printer.Debugf("ebpf: detached libssl uprobes pid=%d (process exited or out of scope)\n", tgt.PID)
				}
				continue
			}
			if err := mgr.AttachLibSSL(tgt.PID, tgt.Lib.HostPath); err != nil {
				printer.Debugf("ebpf: attach pid=%d path=%s failed: %v\n",
					tgt.PID, tgt.Lib.HostPath, err)
				continue
			}
			printer.Debugf("ebpf: attached libssl uprobes pid=%d path=%s\n",
				tgt.PID, tgt.Lib.HostPath)

		case ev, ok := <-reader.Out:
			if !ok {
				return nil
			}
			adapter.Feed(ev, monoEpoch)

		case <-gcTicker.C:
			if n := adapter.GC(time.Now(), args.FlowIdleTimeout); n > 0 {
				printer.Debugf("ebpf: GC dropped %d idle flows\n", n)
			}
		}
	}
}
