// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/postmanlabs/postman-insights-agent/ebpf/discovery"
	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
	"github.com/postmanlabs/postman-insights-agent/ebpf/javatls"
	"github.com/postmanlabs/postman-insights-agent/ebpf/jvm"
	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
	"github.com/postmanlabs/postman-insights-agent/ebpf/uprobes"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// logJavaTLSStatus reports whether the Java TLS programs came up.
func logJavaTLSStatus(requested bool, l *loader.Loader) {
	switch {
	case !requested:
	case l.JavaEnabled():
		if kind, err := l.JavaConnAddresses(); err != nil {
			printer.Stderr.Infof("ebpf: Java HTTPS capture enabled\n")
			printer.Stderr.Warningf("ebpf: Java connections will have no IP addresses or ports: %v\n", err)
		} else if fallback := l.JavaConnAddressesFallback(); fallback != nil {
			printer.Stderr.Infof("ebpf: Java HTTPS capture enabled (connection addresses from tcp_recvmsg, by %s; fexit: %v)\n", kind, fallback)
		} else {
			printer.Stderr.Infof("ebpf: Java HTTPS capture enabled (connection addresses from tcp_recvmsg and tcp_sendmsg, by %s)\n", kind)
		}
	default:
		printer.Stderr.Warningf("ebpf: Java HTTPS capture disabled: %v\n", l.JavaError())
	}
}

// Capture is eBPF HTTPS capture with its BPF programs loaded: Start does
// the part that can fail up front, so the caller knows what it captures
// (Libraries) before it starts, and Run does the rest.
type Capture struct {
	load   LoadArgs
	l      *loader.Loader
	reader *events.Reader
	// javaNetns is the network namespace Java capture is confined to (see
	// LoadArgs.EnableJava), or 0 when unknown.
	javaNetns uint64
	// javaOn: the Java programs loaded and accept frames from javaNetns.
	javaOn bool

	closeOnce sync.Once
}

// Start loads the BPF programs. It fails when none of the libraries asked for
// can be captured: the kernel lacks eBPF support, or only Java was asked for
// and it is not available.
//
// Returns ErrUnsupported on platforms / builds without eBPF.
func Start(load LoadArgs) (*Capture, error) {
	c := &Capture{load: load, javaNetns: netnsInodeAt("/proc/self/ns/net")}
	// The same rule as for a DaemonSet's pods, with the agent's own netns as
	// the pod's.
	if reason := JavaPodSkipReason(c.javaNetns, sidecarNodeNetns()); load.EnableJava && reason != "" {
		printer.Stderr.Warningf("ebpf: Java HTTPS capture disabled: %s\n", reason)
		load.EnableJava = false
	}

	l, err := loader.Load(loader.Config{
		EnforcePIDAllowlist:       load.EnforcePIDAllowlist,
		MaxCaptureBytes:           load.MaxCaptureBytes,
		EnableJava:                load.EnableJava,
		EnforceJavaNetnsAllowlist: true,
	})
	if err != nil {
		return nil, fmt.Errorf("ebpf: load: %w", err)
	}
	c.l = l
	logJavaTLSStatus(load.EnableJava, l)
	if l.JavaEnabled() {
		if err := l.AllowJavaNetns(c.javaNetns); err != nil {
			printer.Stderr.Warningf("ebpf: Java HTTPS capture disabled: %v\n", err)
		} else {
			c.javaOn = true
		}
	}
	if c.Libraries().None() {
		c.Close()
		return nil, fmt.Errorf("ebpf: none of the TLS libraries asked for (%s) can be captured", c.load.Libraries())
	}

	c.reader, err = events.NewReader(l.EventsMap(), 4096)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("ebpf: new reader: %w", err)
	}
	return c, nil
}

// sidecarNodeNetns returns the node's network namespace inode when the agent
// runs in a Kubernetes pod and sees the node's processes (hostPID, which the
// generated sidecars set for HTTPS capture), or 0. A pod on the host network
// shares the node's netns with host processes and other hostNetwork pods, so
// it does not identify the agent's pod (JavaPodSkipReason). An agent run on
// a host, outside Kubernetes, captures the host's JVMs. Without hostPID the
// node's netns cannot be seen, so a hostNetwork pod is not detected.
func sidecarNodeNetns() uint64 {
	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		return 0
	}
	// Kernel threads are visible only in the root PID namespace; PID 2 is
	// kthreadd, so /proc/1 is then the node's init.
	comm, err := os.ReadFile("/proc/2/comm")
	if err != nil || strings.TrimSpace(string(comm)) != "kthreadd" {
		return 0
	}
	return netnsInodeAt("/proc/1/ns/net")
}

// Libraries returns the TLS libraries c captures from.
func (c *Capture) Libraries() Libraries {
	return Libraries{OpenSSL: !c.load.DisableOpenSSL, Java: c.javaOn}
}

// Close releases the BPF programs. Run closes c when it returns; call Close
// only for a Capture that is never run.
func (c *Capture) Close() {
	c.closeOnce.Do(func() {
		if c.reader != nil {
			_ = c.reader.Close()
		}
		_ = c.l.Close()
	})
}

// Collect runs the eBPF HTTPS capture pipeline until ctx is cancelled: Start,
// then Run.
//
// Returns ErrUnsupported on platforms / builds without eBPF.
func Collect(ctx context.Context, args Args) error {
	c, err := Start(args.LoadArgs)
	if err != nil {
		return err
	}
	return c.Run(ctx, args.RunArgs)
}

// Run captures until ctx is cancelled, then closes c.
func (c *Capture) Run(ctx context.Context, args RunArgs) error {
	defer c.Close()
	if args.Out == nil {
		return fmt.Errorf("ebpf: Args.Out is nil")
	}
	if args.FactorySelector == nil {
		return fmt.Errorf("ebpf: Args.FactorySelector is nil")
	}
	l, reader, javaNetns, javaOn := c.l, c.reader, c.javaNetns, c.javaOn

	// Ring-buffer reader.
	readerCtx, cancelReader := context.WithCancel(ctx)
	defer cancelReader()
	go func() {
		if err := reader.Run(readerCtx); err != nil {
			printer.Errorf("ebpf: reader stopped: %v\n", err)
		}
	}()

	// 3. Construct adapter; feed events into akinet parsers → args.Out.
	adapter := events.NewAdapter(args.FactorySelector, args.Out)
	adapter.Resolver = events.NewResolverWithProcRoot(1*time.Second, args.ProcRoot)

	// 4. Start uprobe manager + process discovery.
	mgr := uprobes.NewManager(l)
	defer func() { _ = mgr.Close() }()

	// 4b. CPU thermostat, sampling layer 5 ("Limits and sampling" in
	// docs/https-capture-design.md). Runs for the
	// lifetime of Collect and lowers max_capture_bytes if the agent itself
	// exceeds the CPU budget.
	therm := NewThermostat(l, c.load.MaxCaptureBytes)
	if !args.DisableThermostat {
		go therm.Run(ctx)
	}

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

	// The JVMs in the agent's network namespace get control files, with Java
	// capture on or off. Off, they tell a Java agent an earlier run enabled to
	// stop at the next refresh, rather than once its file goes stale.
	var jvms *jvm.Controller
	if javaNetns != 0 {
		jvms = jvm.NewController(func() javatls.Control {
			return javaControl(javaOn, l, therm, c.load.MaxCaptureBytes)
		})
		go jvms.Run(ctx)
	}
	ownedJVMs := make(map[uint32]jvm.Key)

	var disco <-chan discovery.Target
	if args.Discovery != nil {
		disco = args.Discovery
	} else {
		// Discovery scans the agent-visible /proc (not args.ProcRoot) because
		// uprobe attach via perf_event_open interprets PIDs in the calling
		// process's PID namespace. Using /host/proc here would emit root-ns
		// PIDs that the kernel can't match against the agent's ns view. The
		// resolver (events.NewResolverWithProcRoot above) handles BPF-emitted
		// root-ns PIDs separately and reads /host/proc directly.
		disco = discovery.WatchWith(ctx, discovery.WatchOpts{
			Interval: args.DiscoveryInterval,
			JVMs:     jvms != nil,
		})
	}

	// Establish monotonic-clock epoch so event timestamps map to wall clock.
	// Fatal on failure: without it every witness would carry a bogus timestamp.
	//
	// monoEpoch is owned by the event loop below — it is the only goroutine that
	// reads or updates it, so no locking is needed.
	monoEpoch, err := monotonicEpoch()
	if err != nil {
		return err
	}

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
				if k, ok := ownedJVMs[tgt.PID]; ok {
					delete(ownedJVMs, tgt.PID)
					jvms.Remove(k)
				}
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
			// Discovery emits a PID again when it gains libssl or becomes
			// a JVM; the uprobes manager attaches a PID's libssl once.
			if _, owned := ownedJVMs[tgt.PID]; tgt.JVM != nil && jvms != nil && !owned && jvmNetns(tgt.JVM) == javaNetns {
				jvms.Add(tgt.JVM)
				ownedJVMs[tgt.PID] = tgt.JVM.Key()
			}
			if tgt.Lib == nil || c.load.DisableOpenSSL {
				continue
			}
			if err := mgr.AttachLibSSL(tgt.PID, tgt.Lib.HostPath, tgt.Lib.Static); err != nil {
				printer.Debugf("ebpf: attach pid=%d path=%s failed: %v\n",
					tgt.PID, tgt.Lib.HostPath, err)
				continue
			}
			nProbes := mgr.ProbeCount(tgt.PID)
			printer.Stderr.Infof("ebpf: attached libssl uprobes pid=%d path=%s static=%v probes=%d\n",
				tgt.PID, tgt.Lib.HostPath, tgt.Lib.Static, nProbes)

		case ev, ok := <-reader.Out:
			if !ok {
				return nil
			}
			adapter.Feed(ev, monoEpoch)

		case <-gcTicker.C:
			// Re-check the epoch: if the machine stopped running since the last
			// tick, every witness after the resume would otherwise be back-dated.
			monoEpoch = adjustEpoch(monoEpoch)

			if n := adapter.GC(time.Now(), args.FlowIdleTimeout); n > 0 {
				printer.Debugf("ebpf: GC dropped %d idle flows\n", n)
			}
		}
	}
}
