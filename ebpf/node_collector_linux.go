// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

// NodeCollector loads the eBPF programs once per agent pod (= once per node)
// and fans out captured events to per-pod subscribers. This eliminates the
// N-fold loader.Load() calls that occurred when each per-pod apidump goroutine
// created its own ebpf.Collect() pipeline.
//
// Design:
//   - ONE loader.Load() → one BPF program set, one ring buffer, one uprobe manager.
//   - ONE ring buffer reader goroutine dispatches events to subscribers,
//     primarily by network-namespace inode (see routeSub) with a PID fallback.
//   - ONE thermostat and rate-cap refiller run at the node level.
//   - Per-pod: own discovery channel, own events.Adapter, own out channel.
//     Subscribe() registers the pod; the returned cancel unregisters it.
//
// Routing key: events are routed by the pod's network-namespace inode, which is
// stable across PID namespaces. The BPF-stamped `pid` is the init-namespace
// TGID and does NOT match discovery's node-namespace PID in nested setups
// (KIND / k3d / minikube --driver=docker), so PID is only a fallback for
// non-nested nodes.
//
// Thread safety: netnsToSub and pidToSub are protected by mu. Subscribe/
// unsubscribe and the event-dispatch loop all acquire the appropriate lock.

import (
	"context"
	"sync"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"

	"github.com/postmanlabs/postman-insights-agent/ebpf/discovery"
	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
	"github.com/postmanlabs/postman-insights-agent/ebpf/uprobes"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// podSub and routeSub live in sub.go (build-tag-free) so the routing logic is
// unit-tested on every platform.

// NodeCollector is a node-scoped eBPF coordinator. Create one per agent pod
// via NewNodeCollector, start it with Run, then call Subscribe for each
// monitored workload pod.
type NodeCollector struct {
	ldr   *loader.Loader
	mgr   *uprobes.Manager
	therm *Thermostat

	monoEpoch time.Time

	// flowIdleTimeout is forwarded to per-pod GC tickers.
	flowIdleTimeout time.Duration
	// rateCapPerSec is forwarded to the shared rate-cap refiller.
	rateCapPerSec uint32
	// maxCaptureBytes is the initial BPF capture cap (may be lowered by thermostat).
	maxCaptureBytes uint32

	mu sync.RWMutex
	// netnsToSub is the primary routing table: pod netns inode -> subscriber.
	netnsToSub map[uint64]*podSub
	// pidToSub is a fallback routing table (node-ns PID -> subscriber) used on
	// non-nested nodes where BPF PIDs match discovery PIDs.
	pidToSub map[uint32]*podSub
}

// NodeCollectorConfig mirrors the relevant fields from ebpf.Args used at
// the node level.
type NodeCollectorConfig struct {
	MaxCaptureBytes   uint32
	RateCapPerSec     uint32
	FlowIdleTimeout   time.Duration
	DisableThermostat bool
}

// NewNodeCollector loads the eBPF programs once and returns a NodeCollector
// ready to run. The caller must call Run(ctx) to start the event loop, and
// Close() when done (typically deferred).
func NewNodeCollector(cfg NodeCollectorConfig) (*NodeCollector, error) {
	if cfg.MaxCaptureBytes == 0 {
		cfg.MaxCaptureBytes = 4096
	}
	if cfg.FlowIdleTimeout == 0 {
		cfg.FlowIdleTimeout = 30 * time.Second
	}

	l, err := loader.Load(loader.Config{
		MaxCaptureBytes: cfg.MaxCaptureBytes,
	})
	if err != nil {
		return nil, err
	}

	var therm *Thermostat
	if !cfg.DisableThermostat {
		therm = NewThermostat(l, cfg.MaxCaptureBytes)
	}

	nc := &NodeCollector{
		ldr:             l,
		mgr:             uprobes.NewManager(l),
		therm:           therm,
		monoEpoch:       time.Now().Add(-time.Duration(monotonicNow())),
		flowIdleTimeout: cfg.FlowIdleTimeout,
		rateCapPerSec:   cfg.RateCapPerSec,
		maxCaptureBytes: cfg.MaxCaptureBytes,
		netnsToSub:      make(map[uint64]*podSub),
		pidToSub:        make(map[uint32]*podSub),
	}
	return nc, nil
}

// Close releases all kernel resources. Call after cancelling the context
// passed to Run and after all Subscribe goroutines have returned.
func (nc *NodeCollector) Close() error {
	if nc.mgr != nil {
		_ = nc.mgr.Close()
	}
	if nc.ldr != nil {
		return nc.ldr.Close()
	}
	return nil
}

// Loader returns the underlying loader handle, e.g. for telemetry.
func (nc *NodeCollector) Loader() *loader.Loader { return nc.ldr }

// Thermostat returns the thermostat handle, e.g. for telemetry.
func (nc *NodeCollector) Thermostat() *Thermostat { return nc.therm }

// Manager returns the uprobe manager handle, e.g. for telemetry.
func (nc *NodeCollector) Manager() *uprobes.Manager { return nc.mgr }

// Run starts the shared event-dispatch loop. It blocks until ctx is
// cancelled. Call this in a dedicated goroutine.
func (nc *NodeCollector) Run(ctx context.Context) error {
	reader, err := events.NewReader(nc.ldr.EventsMap(), 4096)
	if err != nil {
		return err
	}
	defer func() { _ = reader.Close() }()

	readerCtx, cancelReader := context.WithCancel(ctx)
	defer cancelReader()
	go func() {
		if err := reader.Run(readerCtx); err != nil {
			printer.Errorf("ebpf: node-collector reader stopped: %v\n", err)
		}
	}()

	if nc.therm != nil {
		go nc.therm.Run(ctx)
	}

	go rateCapRefiller(ctx, nc.ldr, nc.mgr, nc.rateCapPerSec)

	gcTicker := time.NewTicker(nc.flowIdleTimeout / 2)
	defer gcTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil

		case ev, ok := <-reader.Out:
			if !ok {
				return nil
			}
			nc.mu.RLock()
			sub := routeSub(nc.netnsToSub, nc.pidToSub, uint64(ev.NetNS), ev.PID)
			nc.mu.RUnlock()
			if sub != nil {
				sub.adapter.Feed(ev, nc.monoEpoch)
			}

		case <-gcTicker.C:
			nc.mu.RLock()
			adapters := make([]*events.Adapter, 0, len(nc.netnsToSub)+len(nc.pidToSub))
			seen := make(map[*events.Adapter]struct{})
			for _, s := range nc.netnsToSub {
				if _, ok := seen[s.adapter]; !ok {
					adapters = append(adapters, s.adapter)
					seen[s.adapter] = struct{}{}
				}
			}
			for _, s := range nc.pidToSub {
				if _, ok := seen[s.adapter]; !ok {
					adapters = append(adapters, s.adapter)
					seen[s.adapter] = struct{}{}
				}
			}
			nc.mu.RUnlock()
			for _, a := range adapters {
				if n := a.GC(time.Now(), nc.flowIdleTimeout); n > 0 {
					printer.Debugf("ebpf: node-collector GC dropped %d idle flows\n", n)
				}
			}
		}
	}
}

// Subscribe registers a pod subscriber with the NodeCollector. It starts a
// goroutine that drives discovery (attaching/detaching uprobes) and routes
// BPF events for the pod to out via an events.Adapter.
//
// disco is a /proc-scoped discovery channel filtered to the pod's netns inode
// (or namespace). netnsInode is the pod's network-namespace inode and is the
// primary routing key (0 disables netns routing, falling back to PID).
// factorySelector and procRoot mirror the apidump pipeline. out is owned by
// the caller; it is never closed by Subscribe.
//
// Returns a cancel func and the pod's events.Adapter. Call cancel (and drain
// out) when the pod terminates to unregister the pod and stop the subscription
// goroutine. The returned adapter is exposed so the caller can feed its
// per-pod capture counters (MessagesEmitted, FlowsActive) into telemetry.
func (nc *NodeCollector) Subscribe(
	ctx context.Context,
	disco <-chan discovery.Target,
	factorySelector akinet.TCPParserFactorySelector,
	out chan<- akinet.ParsedNetworkTraffic,
	procRoot string,
	netnsInode uint64,
) (context.CancelFunc, *events.Adapter) {
	subCtx, cancel := context.WithCancel(ctx)

	adapter := events.NewAdapter(factorySelector, out)
	adapter.Resolver = events.NewResolverWithProcRoot(1*time.Second, procRoot)

	if adapter.Resolver != nil {
		go preResolveLoop(subCtx, nc.ldr, adapter.Resolver, adapter, 5*time.Millisecond)
	}

	// One subscriber per pod. Register it by netns inode immediately (the netns
	// is known upfront, unlike PIDs which arrive via discovery). This is the key
	// that events actually route on; PID registration below is only a fallback
	// for non-nested nodes.
	sub := &podSub{adapter: adapter, out: out}
	if netnsInode != 0 {
		nc.mu.Lock()
		nc.netnsToSub[netnsInode] = sub
		nc.mu.Unlock()
	}

	go func() {
		// Track which PIDs this subscription registered so we can clean up on
		// cancel even if discovery doesn't emit Removed events in time.
		ownedPIDs := make(map[uint32]struct{})

		for {
			select {
			case <-subCtx.Done():
				// Unregister the pod's netns route and any remaining PIDs.
				nc.mu.Lock()
				if netnsInode != 0 {
					delete(nc.netnsToSub, netnsInode)
				}
				for pid := range ownedPIDs {
					delete(nc.pidToSub, uint32(pid))
				}
				nc.mu.Unlock()
				for pid := range ownedPIDs {
					if err := nc.mgr.Detach(pid); err != nil {
						printer.Debugf("ebpf: subscribe cancel: detach pid=%d: %v\n", pid, err)
					}
					if adapter.Resolver != nil {
						adapter.Resolver.Forget(pid)
					}
				}
				return

			case tgt, ok := <-disco:
				if !ok {
					return
				}
				if tgt.Removed {
					nc.mu.Lock()
					delete(nc.pidToSub, uint32(tgt.PID))
					nc.mu.Unlock()
					delete(ownedPIDs, tgt.PID)
					if err := nc.mgr.Detach(tgt.PID); err != nil {
						printer.Debugf("ebpf: detach pid=%d: %v\n", tgt.PID, err)
					} else {
						printer.Debugf("ebpf: detached libssl uprobes pid=%d (pod exited)\n", tgt.PID)
					}
					if adapter.Resolver != nil {
						adapter.Resolver.Forget(tgt.PID)
					}
					continue
				}

				if err := nc.mgr.AttachLibSSL(tgt.PID, tgt.Lib.HostPath, tgt.Lib.Static); err != nil {
					printer.Debugf("ebpf: attach pid=%d path=%s failed: %v\n",
						tgt.PID, tgt.Lib.HostPath, err)
					continue
				}
				nc.mu.Lock()
				nc.pidToSub[uint32(tgt.PID)] = sub
				nc.mu.Unlock()
				ownedPIDs[tgt.PID] = struct{}{}
				nProbes := nc.mgr.ProbeCount(tgt.PID)
				printer.Stderr.Infof(
					"ebpf: attached libssl uprobes pid=%d path=%s static=%v probes=%d\n",
					tgt.PID, tgt.Lib.HostPath, tgt.Lib.Static, nProbes)
			}
		}
	}()

	return cancel, adapter
}
