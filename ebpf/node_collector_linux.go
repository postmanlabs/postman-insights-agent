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
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"

	"github.com/postmanlabs/postman-insights-agent/ebpf/discovery"
	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
	"github.com/postmanlabs/postman-insights-agent/ebpf/javatls"
	"github.com/postmanlabs/postman-insights-agent/ebpf/jvm"
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

	// monoEpoch maps BPF timestamps onto wall clock. It is owned exclusively by
	// Run's event loop — the only goroutine that reads or updates it — so it
	// needs no locking. Run periodically re-checks it via adjustEpoch.
	monoEpoch time.Time

	// flowIdleTimeout is forwarded to per-pod GC tickers.
	flowIdleTimeout time.Duration
	// rateCapPerSec is forwarded to the shared rate-cap refiller.
	rateCapPerSec uint32
	// maxCaptureBytes is the initial BPF capture cap (may be lowered by thermostat).
	maxCaptureBytes uint32
	// openSSL attaches libssl uprobes to discovered processes; off when only
	// Java is captured.
	openSSL bool

	mu sync.RWMutex
	// netnsToSub is the primary routing table: pod netns inode -> subscribers.
	netnsToSub routeTable[uint64]
	// pidToSub is a fallback routing table (node-ns PID -> subscribers) used on
	// non-nested nodes where BPF PIDs match discovery PIDs. It also records
	// which subscriptions use a PID's uprobes (see attachPID).
	pidToSub routeTable[uint32]

	// probeMu serializes attaching and detaching uprobes with the pidToSub
	// bookkeeping, so a detach for one subscription cannot interleave with
	// another subscription attaching the same PID.
	probeMu sync.Mutex

	// hostNetns is the node's own network namespace, which every hostNetwork
	// pod and every host process shares. Java frames are never accepted from
	// it: a netns there does not identify one pod. 0 when unknown.
	hostNetns uint64
	// javaNetnsRefs counts the subscriptions that allowed each netns for Java
	// frames, so one subscription's cancel cannot revoke another's. Guarded by
	// mu.
	javaNetnsRefs map[uint64]int

	// jvms keeps the Java agents' control files fresh for the JVMs in
	// subscribed pods, and switches the agents off when Java capture is off.
	jvms *jvm.Controller
	// attacher loads the Java agent into those JVMs. Nil when Java capture
	// is off or the agent jar or helper is missing; JVMs started with
	// -javaagent are captured all the same.
	attacher *jvm.Attacher
}

// NodeCollectorConfig mirrors the relevant fields from ebpf.Args used at
// the node level.
type NodeCollectorConfig struct {
	MaxCaptureBytes   uint32
	RateCapPerSec     uint32
	FlowIdleTimeout   time.Duration
	DisableThermostat bool

	// EnableJava also loads the Java TLS programs, which accept frames only
	// from the network namespaces of subscribed pods.
	EnableJava bool

	// DisableOpenSSL attaches no libssl uprobes, so only Java is captured.
	DisableOpenSSL bool
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

	// Establish the monotonic→wall-clock epoch before loading anything, so that
	// a clock failure aborts startup without leaking loaded BPF programs.
	monoEpoch, err := monotonicEpoch()
	if err != nil {
		return nil, err
	}

	l, err := loader.Load(loader.Config{
		MaxCaptureBytes:           cfg.MaxCaptureBytes,
		EnableJava:                cfg.EnableJava,
		EnforceJavaNetnsAllowlist: true,
	})
	if err != nil {
		return nil, err
	}
	logJavaTLSStatus(cfg.EnableJava, l)

	var therm *Thermostat
	if !cfg.DisableThermostat {
		therm = NewThermostat(l, cfg.MaxCaptureBytes)
	}

	nc := &NodeCollector{
		ldr:             l,
		mgr:             uprobes.NewManager(l),
		therm:           therm,
		monoEpoch:       monoEpoch,
		flowIdleTimeout: cfg.FlowIdleTimeout,
		rateCapPerSec:   cfg.RateCapPerSec,
		maxCaptureBytes: cfg.MaxCaptureBytes,
		openSSL:         !cfg.DisableOpenSSL,
		netnsToSub:      routeTable[uint64]{},
		pidToSub:        routeTable[uint32]{},
		hostNetns:       hostNetnsInode(),
		javaNetnsRefs:   make(map[uint64]int),
	}
	javaSettings := func() javatls.Control {
		return javaControl(cfg.EnableJava, l, therm, cfg.MaxCaptureBytes)
	}
	nc.jvms = jvm.NewController(javaSettings)
	if javaSettings().Enabled {
		a, err := jvm.NewAttacher(jvm.AttacherConfig{
			HelperPath:   javatls.AttachHelperPath,
			JarPath:      javatls.AgentJarPath,
			ChecksumPath: javatls.AgentJarChecksumPath,
			AgentArgs: func() string {
				return javatls.ArgCaptureCap + "=" + strconv.Itoa(javaSettings().CaptureCap)
			},
		})
		if err != nil {
			printer.Stderr.Warningf("ebpf: Java agent cannot be attached to running JVMs (%v); "+
				"JVMs started with -javaagent are still captured\n", err)
		} else {
			nc.attacher = a
		}
	}
	return nc, nil
}

// hostNetnsInode returns the network-namespace inode of PID 1 as the agent
// sees it. With hostPID (the DaemonSet) that is the node's init, whose netns
// hostNetwork pods share; in kind it is the node container's. Without hostPID
// it is the agent pod's own netns, which is never a monitored pod's.
func hostNetnsInode() uint64 { return netnsInodeAt("/proc/1/ns/net") }

// netnsInodeAt returns the inode of the network namespace at path (a
// /proc/<pid>/ns/net), or 0.
func netnsInodeAt(path string) uint64 {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0
	}
	return st.Ino
}

// jvmNetns returns the network namespace inode of p, or 0.
func jvmNetns(p *jvm.Process) uint64 {
	return netnsInodeAt(filepath.Join(p.ProcRoot, strconv.FormatUint(uint64(p.PID), 10), "ns", "net"))
}

// attachPID attaches libssl uprobes to pid for sub and routes the PID to it.
// The uprobes manager attaches once per PID, and two subscriptions can share a
// PID (hostNetwork pods), so pidToSub records every subscription using the
// probes and releasePID detaches only when the last one leaves.
func (nc *NodeCollector) attachPID(tgt discovery.Target, sub *podSub) error {
	nc.probeMu.Lock()
	defer nc.probeMu.Unlock()
	if err := nc.mgr.AttachLibSSL(tgt.PID, tgt.Lib.HostPath, tgt.Lib.Static); err != nil {
		return err
	}
	nc.mu.Lock()
	nc.pidToSub.add(tgt.PID, sub)
	nc.mu.Unlock()
	return nil
}

// releasePID undoes attachPID for sub, and detaches the uprobes if no other
// subscription uses them. Reports whether it detached.
func (nc *NodeCollector) releasePID(pid uint32, sub *podSub) (bool, error) {
	nc.probeMu.Lock()
	defer nc.probeMu.Unlock()
	nc.mu.Lock()
	nc.pidToSub.remove(pid, sub)
	last := nc.pidToSub.get(pid) == nil
	nc.mu.Unlock()
	if !last {
		return false, nil
	}
	return true, nc.mgr.Detach(pid)
}

// allowJavaNetns accepts Java frames from a subscribed pod's netns. It
// refuses the node's own netns, shared by hostNetwork pods and host processes.
func (nc *NodeCollector) allowJavaNetns(netnsInode uint64) bool {
	if !nc.ldr.JavaEnabled() || netnsInode == 0 {
		return false
	}
	if netnsInode == nc.hostNetns {
		printer.Stderr.Infof("ebpf: Java HTTPS capture skipped for a pod on the host network (netns %d)\n", netnsInode)
		return false
	}
	nc.mu.Lock()
	defer nc.mu.Unlock()
	if nc.javaNetnsRefs[netnsInode] == 0 {
		if err := nc.ldr.AllowJavaNetns(netnsInode); err != nil {
			printer.Stderr.Warningf("ebpf: Java HTTPS capture not enabled for netns %d: %v\n", netnsInode, err)
			return false
		}
	}
	nc.javaNetnsRefs[netnsInode]++
	return true
}

// releaseJavaNetns undoes one allowJavaNetns.
func (nc *NodeCollector) releaseJavaNetns(netnsInode uint64) {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	nc.javaNetnsRefs[netnsInode]--
	if nc.javaNetnsRefs[netnsInode] > 0 {
		return
	}
	delete(nc.javaNetnsRefs, netnsInode)
	if err := nc.ldr.DisallowJavaNetns(netnsInode); err != nil {
		printer.Debugf("ebpf: disallow Java netns %d: %v\n", netnsInode, err)
	}
}

// addJVM writes the control file for a JVM in a subscribed pod, then queues
// it for attaching, so an attached agent finds the file at once. report, when
// not nil, receives the pod's JVM telemetry events: the JVM seen, counted
// here because the attacher is absent when Java capture is off or attach is
// unavailable, and its attach outcome.
func (nc *NodeCollector) addJVM(p *jvm.Process, report func(event string)) {
	// Seen once per JVM, also when a replacement subscription for the same
	// pod adds it before the one it replaces has removed it.
	if nc.jvms.Add(p) && report != nil {
		report(jvm.EventSeen)
	}
	if nc.attacher != nil {
		nc.attacher.Add(p, report)
	}
}

// removeJVM undoes addJVM.
func (nc *NodeCollector) removeJVM(k jvm.Key) {
	nc.jvms.Remove(k)
	if nc.attacher != nil {
		nc.attacher.Remove(k)
	}
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

// JVMStats returns what happened to the JVMs of subscribed pods so far, and
// false when no JVMs are attached (Java capture off, or attach unavailable).
func (nc *NodeCollector) JVMStats() (jvm.AttachStats, bool) {
	if nc.attacher == nil {
		return jvm.AttachStats{}, false
	}
	return nc.attacher.Stats(), true
}

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

	go nc.jvms.Run(ctx)
	if nc.attacher != nil {
		go nc.attacher.Run(ctx)
	}

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
			// Re-check the epoch: if the machine stopped running since the last
			// tick, every witness after the resume would otherwise be back-dated.
			nc.monoEpoch = adjustEpoch(nc.monoEpoch)

			nc.mu.RLock()
			adapters := make([]*events.Adapter, 0, len(nc.netnsToSub)+len(nc.pidToSub))
			seen := make(map[*events.Adapter]struct{})
			for _, subs := range nc.netnsToSub {
				for _, s := range subs {
					if _, ok := seen[s.adapter]; !ok {
						adapters = append(adapters, s.adapter)
						seen[s.adapter] = struct{}{}
					}
				}
			}
			for _, subs := range nc.pidToSub {
				for _, s := range subs {
					if _, ok := seen[s.adapter]; !ok {
						adapters = append(adapters, s.adapter)
						seen[s.adapter] = struct{}{}
					}
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
// the caller; it is never closed by Subscribe. reportCount, when not nil,
// receives the pod's telemetry counters (the attach outcome of its JVMs).
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
	reportCount func(event string, count uint64),
) (context.CancelFunc, *events.Adapter) {
	subCtx, cancel := context.WithCancel(ctx)

	var reportJVM func(event string)
	if reportCount != nil {
		reportJVM = func(event string) { reportCount(event, 1) }
	}

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
		nc.netnsToSub.add(netnsInode, sub)
		nc.mu.Unlock()
	}
	// Java frames are accepted per pod netns, the same key events route on.
	javaNetns := nc.allowJavaNetns(netnsInode)
	// The JVMs of a pod known by its own netns get control files, also with
	// Java capture off (to switch earlier agents off). Never on the host
	// network, where a netns does not identify one pod.
	jvmScope := netnsInode != 0 && netnsInode != nc.hostNetns

	go func() {
		// Track which PIDs this subscription registered so we can clean up on
		// cancel even if discovery doesn't emit Removed events in time.
		ownedPIDs := make(map[uint32]struct{})
		ownedJVMs := make(map[uint32]jvm.Key)

		// Unregister the pod's netns route, its Java allowlist entry and any
		// remaining PIDs. Runs however the loop ends: discovery closes its
		// channel when the capture context ends, which can be seen first.
		defer func() {
			if netnsInode != 0 {
				nc.mu.Lock()
				nc.netnsToSub.remove(netnsInode, sub)
				nc.mu.Unlock()
			}
			if javaNetns {
				nc.releaseJavaNetns(netnsInode)
			}
			for _, k := range ownedJVMs {
				nc.removeJVM(k)
			}
			for pid := range ownedPIDs {
				if _, err := nc.releasePID(pid, sub); err != nil {
					printer.Debugf("ebpf: subscribe cancel: detach pid=%d: %v\n", pid, err)
				}
				if adapter.Resolver != nil {
					adapter.Resolver.Forget(pid)
				}
			}
		}()

		for {
			select {
			case <-subCtx.Done():
				return

			case tgt, ok := <-disco:
				if !ok {
					return
				}
				if tgt.Removed {
					if k, ok := ownedJVMs[tgt.PID]; ok {
						delete(ownedJVMs, tgt.PID)
						nc.removeJVM(k)
					}
					delete(ownedPIDs, tgt.PID)
					if detached, err := nc.releasePID(tgt.PID, sub); err != nil {
						printer.Debugf("ebpf: detach pid=%d: %v\n", tgt.PID, err)
					} else if detached {
						printer.Debugf("ebpf: detached libssl uprobes pid=%d (pod exited)\n", tgt.PID)
					}
					if adapter.Resolver != nil {
						adapter.Resolver.Forget(tgt.PID)
					}
					continue
				}

				// Discovery emits a PID again when it gains libssl or
				// becomes a JVM: add only what is new.
				if _, owned := ownedJVMs[tgt.PID]; tgt.JVM != nil && jvmScope && !owned {
					nc.addJVM(tgt.JVM, reportJVM)
					ownedJVMs[tgt.PID] = tgt.JVM.Key()
				}
				if _, owned := ownedPIDs[tgt.PID]; tgt.Lib == nil || owned || !nc.openSSL {
					continue
				}
				if err := nc.attachPID(tgt, sub); err != nil {
					printer.Debugf("ebpf: attach pid=%d path=%s failed: %v\n",
						tgt.PID, tgt.Lib.HostPath, err)
					continue
				}
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
