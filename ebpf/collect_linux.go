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

	// RateCapPerSec is the per-PID rate cap (events/sec) for sampling layer 2.
	// 0 disables rate limiting. The kernel takes one token per event; the
	// userspace refiller resets buckets every second.
	RateCapPerSec uint32

	// Discovery is an optional pre-built discovery channel. When nil,
	// Collect builds its own via discovery.Watch (spike behaviour). Set this
	// to use WatchWith with namespace filtering or a custom CRI integration.
	Discovery DiscoveryChan

	// Loader observability: Thermostat / counter access is via the returned
	// Stats interface (see Stats()). Set HookLoader to receive the loader
	// handle for telemetry wiring; the lifecycle remains owned by Collect.
	HookLoader func(*loader.Loader, *Thermostat, *uprobes.Manager, *events.Adapter)
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
	adapter.Resolver = events.NewResolver(1 * time.Second)

	// 4. Start uprobe manager + process discovery.
	mgr := uprobes.NewManager(l)
	defer func() { _ = mgr.Close() }()

	// 4b. CPU thermostat — sampling layer 5 (design doc §6.2). Runs for the
	// lifetime of Collect and lowers max_capture_bytes if the agent itself
	// exceeds the CPU budget.
	therm := NewThermostat(l, args.MaxCaptureBytes)
	go therm.Run(ctx)

	// 4c. Per-PID rate cap — sampling layer 2.
	go rateCapRefiller(ctx, l, mgr, args.RateCapPerSec)

	// 4d. Proactive (pid, ssl_ctx) → 4-tuple resolver: scans the BPF
	// ssl_ctx_to_fd map every 5ms while sockets are still alive, caches
	// results on the adapter so late-arriving events still get IPs even
	// after the connection has closed. The 5ms interval is calibrated for
	// the worst-case loopback test: a curl HTTPS request completes in ~5ms,
	// so a 100ms poll would miss almost everything. In production, where
	// connections live milliseconds-to-minutes, the polling cost is
	// negligible and effectiveness is high.
	if adapter.Resolver != nil {
		go preResolveLoop(ctx, l, adapter.Resolver, adapter, 5*time.Millisecond)
	}

	// Expose subsystem handles to the caller's telemetry hook (now that all
	// of loader/thermostat/manager/adapter are wired up).
	if args.HookLoader != nil {
		args.HookLoader(l, therm, mgr, adapter)
	}

	var disco <-chan discovery.Target
	if args.Discovery != nil {
		disco = args.Discovery
	} else {
		disco = discovery.Watch(ctx, args.DiscoveryInterval)
	}

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
				if adapter.Resolver != nil {
					adapter.Resolver.Forget(tgt.PID)
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
