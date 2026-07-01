// SPDX-License-Identifier: Apache-2.0

package apidump

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	akihttp "github.com/akitasoftware/akita-libs/akinet/http"
	"github.com/akitasoftware/akita-libs/buffer_pool"

	"github.com/postmanlabs/postman-insights-agent/ebpf"
	"github.com/postmanlabs/postman-insights-agent/ebpf/discovery"
	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
	"github.com/postmanlabs/postman-insights-agent/ebpf/uprobes"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
	"github.com/postmanlabs/postman-insights-agent/trace"
)

// HTTPSCaptureStats is a point-in-time snapshot of the eBPF HTTPS capture
// subsystem, suitable for logging or shipping to the telemetry pipeline.
type HTTPSCaptureStats struct {
	ProbesAttached  int
	FlowsActive     int
	EventsEmitted   uint64
	EventsDropped   uint64 // ringbuf full
	ReadFailures    uint64 // probe_read_user failures
	BytesCaptured   uint64
	MessagesEmitted uint64 // HTTP messages parsed (from adapter)
	FlowsDropped    uint64 // adapter flow drops (parse error / oversize)
	CurrentCapBytes uint32 // current max_capture_bytes (thermostat-adjusted)
	CPUPercent      float64
}

// String produces a single-line, customer-readable summary suitable for
// 'kubectl logs'-style consumption.
func (s HTTPSCaptureStats) String() string {
	return fmt.Sprintf(
		"probes=%d flows_active=%d events=%d bytes=%d msgs=%d "+
			"dropped_ringbuf=%d dropped_flows=%d read_failures=%d "+
			"cap_bytes=%d cpu=%.1f%%",
		s.ProbesAttached, s.FlowsActive, s.EventsEmitted, s.BytesCaptured,
		s.MessagesEmitted, s.EventsDropped, s.FlowsDropped, s.ReadFailures,
		s.CurrentCapBytes, s.CPUPercent)
}

// httpsTelemetryWorker emits HTTPSCaptureStats every `interval` to the log
// stream and to the analytics pipeline. Stops when ctx is cancelled.
func httpsTelemetryWorker(
	ctx context.Context,
	interval time.Duration,
	ldr *loader.Loader,
	therm *ebpf.Thermostat,
	mgr *uprobes.Manager,
	adapter *events.Adapter,
	tracker telemetry.Tracker,
) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	read := func() HTTPSCaptureStats {
		s := HTTPSCaptureStats{}
		if mgr != nil {
			s.ProbesAttached = len(mgr.AttachedPIDs())
		}
		if adapter != nil {
			s.FlowsActive, _ = adapter.Snapshot()
			s.MessagesEmitted = adapter.MessagesEmitted
			s.FlowsDropped = adapter.FlowsDropped
		}
		if ldr != nil {
			if v, err := ldr.ReadCounter(loader.CounterEventsEmitted); err == nil {
				s.EventsEmitted = v
			}
			if v, err := ldr.ReadCounter(loader.CounterEventsDropped); err == nil {
				s.EventsDropped = v
			}
			if v, err := ldr.ReadCounter(loader.CounterReadFailed); err == nil {
				s.ReadFailures = v
			}
			if v, err := ldr.ReadCounter(loader.CounterBytesCaptured); err == nil {
				s.BytesCaptured = v
			}
		}
		if therm != nil {
			s.CurrentCapBytes = therm.CurrentCap()
			s.CPUPercent = therm.CPUPercent()
		}
		return s
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s := read()
			printer.Stderr.Infof("ebpf-stats: %s\n", s.String())
			if tracker != nil {
				tracker.WorkflowStep("ebpf_capture_stats", s.String())
			}
		}
	}
}

// startHTTPSeBPFCapture launches the eBPF HTTPS capture pipeline in its own
// goroutine and returns a stop function. The pipeline pushes
// akinet.ParsedNetworkTraffic into a dedicated collector chain built in
// apidump.go — NOT the same collector instance as the pcap path, but one that
// shares the same backend learn session (backendLrn) so all traffic lands in
// the same trace on Postman. There is no second parallel learn session.
//
// The eBPF collector chain mirrors the pcap chain (redaction, rate limiting,
// path/host filters, backend sink) but intentionally omits tls_conn_tracker
// and tcp_conn_tracker: eBPF delivers already-decrypted plaintext HTTP, not
// raw TLS records or TCP segments.
//
// On builds without `insights_bpf` (or non-Linux), ebpf.Collect returns
// ebpf.ErrUnsupported immediately; this function logs a warning and returns
// a no-op stop.
//
// `pool` is shared with the pcap pipeline so memview buffers are pooled
// consistently across both capture paths.
func startHTTPSeBPFCapture(
	ctx context.Context,
	args *Args,
	pool buffer_pool.BufferPool,
	collector trace.Collector,
	wg *sync.WaitGroup,
	tracker telemetry.Tracker,
) (stop context.CancelFunc) {
	captureCtx, cancel := context.WithCancel(ctx)

	// Channel between the ebpf adapter and the channel→collector pump.
	// Sized larger than the pcap equivalent (100) because the eBPF ringbuf can
	// burst many events back-to-back when a high-throughput SSL session drains;
	// a shallow channel would block the ringbuf reader and cause event drops.
	const ebpfParsedTrafficChanSize = 1024
	out := make(chan akinet.ParsedNetworkTraffic, ebpfParsedTrafficChanSize)

	// Same parser factories the pcap path uses. Note: TLS handshake parser
	// is intentionally NOT here \u2014 the eBPF path delivers post-decryption
	// bytes, so the bytes that arrive on `out` are already plaintext HTTP.
	factories := []akinet.TCPParserFactory{
		akihttp.NewHTTPRequestParserFactory(pool),
		akihttp.NewHTTPResponseParserFactory(pool),
	}
	selector := akinet.TCPParserFactorySelector(factories)

	bodyCap := args.HTTPS.BodySizeCap
	if bodyCap == 0 {
		bodyCap = 1024
	}

	ebpfArgs := ebpf.Defaults()
	ebpfArgs.MaxCaptureBytes = bodyCap
	ebpfArgs.EnforcePIDAllowlist = false
	ebpfArgs.FactorySelector = selector
	ebpfArgs.Out = out
	ebpfArgs.RateCapPerSec = args.HTTPS.RateCapPerSec

	// DaemonSet deployments bind-mount the kernel's root /proc to /host/proc.
	// When present, use it for resolver lookups so BPF-emitted root-ns PIDs
	// match /proc entries. Outside of DaemonSets, /proc is correct.
	if _, err := os.Stat("/host/proc/self"); err == nil {
		ebpfArgs.ProcRoot = "/host/proc"
	}

	// eBPF uprobes are NOT network-namespace confined (unlike libpcap), so
	// explicit filtering is required. Two mechanisms, priority order:
	//
	//  1. ContainerNetnsInode (pod-level, preferred in DaemonSet path)
	//     Filters by /proc/<pid>/ns/net inode — exactly the processes inside
	//     one container's network namespace. Eliminates N× duplicate captures
	//     for scaled (multi-replica) pods.
	//
	//  2. TargetNamespaces (namespace-level, standalone apidump / fallback)
	//     Restricts discovery to named Kubernetes namespaces via
	//     KubeNamespaceResolver. May cause duplicate captures when a namespace
	//     has multiple replicas. Used when ContainerNetnsInode is unavailable.
	switch {
	case args.HTTPS.ContainerNetnsInode != 0:
		printer.Stderr.Infof(
			"ebpf: pod-level netns filtering enabled (inode=%d)\n",
			args.HTTPS.ContainerNetnsInode)
		ebpfArgs.Discovery = discovery.WatchWith(captureCtx, discovery.WatchOpts{
			Interval:         2 * time.Second,
			ProcRoot:         ebpfArgs.ProcRoot,
			NetnsInodeFilter: args.HTTPS.ContainerNetnsInode,
		})

	case len(args.HTTPS.TargetNamespaces) > 0:
		procRoot := "/proc"
		if _, err := os.Stat("/host/proc/self"); err == nil {
			procRoot = "/host/proc"
		}
		// agentProcRoot is always /proc — that's the agent's own PID-namespace
		// view, where CRI-returned container init PIDs live.
		// procRoot is /host/proc on a DaemonSet (root-ns PIDs that BPF emits).
		resolver, err := discovery.NewKubeNamespaceResolver(procRoot, "/proc")
		if err != nil {
			printer.Stderr.Warningf(
				"ebpf: --https-target-namespaces set but kube client init failed (%v); "+
					"falling back to no namespace filtering.\n", err)
		} else {
			allowed := make(map[string]struct{}, len(args.HTTPS.TargetNamespaces))
			for _, ns := range args.HTTPS.TargetNamespaces {
				allowed[ns] = struct{}{}
			}
			printer.Stderr.Infof(
				"ebpf: namespace-level filtering enabled — allowed namespaces: %v\n",
				args.HTTPS.TargetNamespaces)

			// Drive a 30s refresh in the background so new pods become
			// visible without restarting the agent.
			stop := make(chan struct{})
			go func() {
				<-captureCtx.Done()
				close(stop)
				resolver.Close()
			}()
			go resolver.RunRefresh(stop, 30*time.Second)

			ebpfArgs.Discovery = discovery.WatchWith(captureCtx, discovery.WatchOpts{
				Interval:          2 * time.Second,
				NamespaceResolver: resolver,
				AllowedNamespaces: allowed,
			})
		}
	}

	// HookLoader captures the subsystem handles after Collect has wired them
	// up, so the telemetry goroutine can read counters / probe counts / etc.
	ebpfArgs.HookLoader = func(
		ldr *loader.Loader, therm *ebpf.Thermostat,
		mgr *uprobes.Manager, adapter *events.Adapter,
	) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			httpsTelemetryWorker(captureCtx, 30*time.Second, ldr, therm, mgr, adapter, tracker)
		}()
	}

	// Pump: read parsed traffic, hand to the collector chain.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-captureCtx.Done():
				return
			case pnt, ok := <-out:
				if !ok {
					return
				}
				if err := collector.Process(pnt); err != nil {
					printer.Stderr.Warningf("ebpf: collector.Process: %v\n", err)
				}
			}
		}
	}()

	// Actual eBPF collect loop (libssl uprobes).
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(out)
		if err := ebpf.Collect(captureCtx, ebpfArgs); err != nil {
			printer.Stderr.Warningf("ebpf: capture stopped: %v\n", err)
		}
	}()

	// Java TLS capture — attaches the java_tls kprobe that intercepts the
	// postman-java-agent ioctl bridge (SSLEngine.wrap/unwrap → ioctl(0,
	// 0x0b10b1, …) → kernel kprobe → ringbuf). Feeds the same `out` channel
	// and therefore the same collector chain as the libssl path above.
	// Requires postman-java-agent.jar injected into target JVMs via the
	// kube-webhook or manually via JAVA_TOOL_OPTIONS.
	if args.HTTPS.EnableJavaTLS {
		javaAdapter := events.NewAdapter(selector, out)
		javaCollector, err := ebpf.NewJavaTLSCollector(bodyCap, false, javaAdapter)
		if err != nil {
			printer.Stderr.Warningf(
				"ebpf: java_tls kprobe unavailable (build without insights_bpf tag?): %v\n", err)
		} else {
			if err := javaCollector.Attach(); err != nil {
				printer.Stderr.Warningf("ebpf: java_tls attach failed: %v\n", err)
				_ = javaCollector.Close()
			} else {
				printer.Stderr.Infof("ebpf: attached java_tls kprobe (JVM ioctl bridge)\n")
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() { _ = javaCollector.Close() }()
					javaCollector.Run(captureCtx, time.Now())
				}()
			}
		}
	}

	return cancel
}
