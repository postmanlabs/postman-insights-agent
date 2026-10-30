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
	"github.com/postmanlabs/postman-insights-agent/ebpf/jvm"
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
	H2HPACKDesyncs  uint64 // HTTP/2 connections dropped due to HPACK desync (mid-attach)
	CurrentCapBytes uint32 // current max_capture_bytes (thermostat-adjusted)
	CPUPercent      float64

	// Java TLS capture; only reported when its programs are running.
	JavaEnabled       bool
	JavaFrames        uint64 // frames written by Java agents on this node
	JavaEvents        uint64 // frames forwarded as events
	JavaDropped       uint64 // ring buffer full
	JavaNetnsRejected uint64 // frames from pods that are not monitored
	JavaMalformed     uint64 // frames that failed validation
	JavaConnUnbound   uint64 // data frames sent without their connection's addresses
	JavaConnMismatch  uint64 // a connection's thread read another socket before its frame

	// What happened to the JVMs of monitored pods on this node; only
	// reported where the Java agent is attached to running JVMs.
	JVMAttach        bool
	JVMsSeen         uint64
	JVMsAttached     uint64
	JVMsAgentRunning uint64 // already ran the agent (-javaagent, or attached earlier)
	JVMsAgentOther   uint64 // of those, attached earlier with another agent version
	JVMsSkipped      uint64 // not attachable by design (OpenJ9, attach disabled, -Xrs)
	JVMsAttachFailed uint64

	// Java agents in this target heard from recently (HEARTBEAT), and those
	// of them capturing rather than dormant.
	JavaAgentsAlive     int
	JavaAgentsCapturing int
}

// String produces a single-line, customer-readable summary suitable for
// 'kubectl logs'-style consumption.
func (s HTTPSCaptureStats) String() string {
	line := fmt.Sprintf(
		"probes=%d flows_active=%d events=%d bytes=%d msgs=%d "+
			"dropped_ringbuf=%d dropped_flows=%d read_failures=%d "+
			"h2_hpack_desyncs=%d cap_bytes=%d cpu=%.1f%%",
		s.ProbesAttached, s.FlowsActive, s.EventsEmitted, s.BytesCaptured,
		s.MessagesEmitted, s.EventsDropped, s.FlowsDropped, s.ReadFailures,
		s.H2HPACKDesyncs, s.CurrentCapBytes, s.CPUPercent)
	if s.JavaEnabled {
		line += fmt.Sprintf(
			" java_frames=%d java_events=%d java_dropped_ringbuf=%d java_netns_rejected=%d java_malformed=%d"+
				" java_conn_unbound=%d java_conn_mismatch=%d java_agents_alive=%d java_agents_capturing=%d",
			s.JavaFrames, s.JavaEvents, s.JavaDropped, s.JavaNetnsRejected, s.JavaMalformed,
			s.JavaConnUnbound, s.JavaConnMismatch, s.JavaAgentsAlive, s.JavaAgentsCapturing)
	}
	if s.JVMAttach {
		line += fmt.Sprintf(
			" jvms=%d jvms_attached=%d jvms_agent_running=%d jvms_agent_other_version=%d jvms_skipped=%d jvms_attach_failed=%d",
			s.JVMsSeen, s.JVMsAttached, s.JVMsAgentRunning, s.JVMsAgentOther, s.JVMsSkipped, s.JVMsAttachFailed)
	}
	return line
}

// statsLogLine is the ebpf-stats log line for s, naming pod when it is set.
func statsLogLine(pod string, s HTTPSCaptureStats) string {
	if pod == "" {
		return "ebpf-stats: " + s.String()
	}
	return "ebpf-stats: pod=" + pod + " " + s.String()
}

// sumCounts adds up per-reason counters.
func sumCounts(m map[string]uint64) uint64 {
	var n uint64
	for _, v := range m {
		n += v
	}
	return n
}

// httpsTelemetryWorker emits HTTPSCaptureStats every `interval` to the log
// stream and to the analytics pipeline. Stops when ctx is cancelled. pod, when
// not empty, names the monitored pod on the log line: a DaemonSet logs one
// line per pod, and the per-pod counters (msgs, flows_active) differ.
func httpsTelemetryWorker(
	ctx context.Context,
	interval time.Duration,
	ldr *loader.Loader,
	therm *ebpf.Thermostat,
	mgr *uprobes.Manager,
	adapter *events.Adapter,
	jvmStats func() (jvm.AttachStats, bool),
	tracker telemetry.Tracker,
	reportCount func(string, uint64),
	pod string,
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
			adapterStats := adapter.Stats()
			s.MessagesEmitted = adapterStats.MessagesEmitted
			s.FlowsDropped = adapterStats.FlowsDropped
			s.H2HPACKDesyncs = adapterStats.H2HPACKDesyncs
			s.JavaAgentsAlive = adapterStats.JavaAgentsAlive
			s.JavaAgentsCapturing = adapterStats.JavaAgentsCapturing
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
			if ldr.JavaEnabled() {
				s.JavaEnabled = true
				for _, c := range []struct {
					idx uint32
					dst *uint64
				}{
					{loader.JavaCounterFramesSeen, &s.JavaFrames},
					{loader.JavaCounterEventsEmitted, &s.JavaEvents},
					{loader.JavaCounterEventsDropped, &s.JavaDropped},
					{loader.JavaCounterNetnsRejected, &s.JavaNetnsRejected},
					{loader.JavaCounterMalformed, &s.JavaMalformed},
					{loader.JavaCounterConnUnbound, &s.JavaConnUnbound},
					{loader.JavaCounterConnMismatch, &s.JavaConnMismatch},
				} {
					if v, err := ldr.ReadJavaCounter(c.idx); err == nil {
						*c.dst = v
					}
				}
			}
		}
		if therm != nil {
			s.CurrentCapBytes = therm.CurrentCap()
			s.CPUPercent = therm.CPUPercent()
		}
		if jvmStats != nil {
			if st, ok := jvmStats(); ok {
				s.JVMAttach = true
				s.JVMsSeen = st.Seen
				s.JVMsAttached = st.Attached
				s.JVMsAgentRunning = st.AlreadyRunning
				s.JVMsAgentOther = st.OtherVersion
				s.JVMsSkipped = sumCounts(st.Skipped)
				s.JVMsAttachFailed = sumCounts(st.Failed)
			}
		}
		return s
	}

	var previous HTTPSCaptureStats

	// Separate from the log line below because it also runs on cancellation,
	// where the BPF maps behind the logged fields may already be gone.
	reportDeltas := func(s HTTPSCaptureStats) {
		if reportCount == nil {
			return
		}
		reportCount("ebpf_flow_dropped", counterDelta(s.FlowsDropped, previous.FlowsDropped))
		reportCount("ebpf_h2_hpack_desync", counterDelta(s.H2HPACKDesyncs, previous.H2HPACKDesyncs))
	}

	for {
		select {
		case <-ctx.Done():
			// Read once more before returning, so the last interval is not
			// lost. Reporting only on the ticker discarded up to `interval`
			// (30s) of these counters on every shutdown, and a session shorter
			// than one interval reported none of them at all -- which is
			// exactly the session where drops matter most. pollPcapStats's
			// done branch and TelemetryWorker's do the same thing.
			//
			// Safe after cancellation: both counters reported here come from
			// adapter.Stats(), a mutex-guarded read of Go-side fields, not
			// from the BPF maps that teardown may already have closed. No
			// ebpf-stats line is logged here for that reason -- its
			// loader-derived fields would read zero post-teardown and look
			// like a collapse in capture rather than an artifact of shutdown.
			reportDeltas(read())
			return
		case <-t.C:
			s := read()
			reportDeltas(s)
			previous = s
			printer.Stderr.Infof("%s\n", statsLogLine(pod, s))
			if tracker != nil {
				tracker.WorkflowStep("ebpf_capture_stats", s.String())
			}
		}
	}
}

// httpsCapture is HTTPS capture via eBPF for one apidump run. It is set up in
// two steps. prepareHTTPSCapture decides whether it runs, and from which
// libraries, before the pcap filters are final: pcap leaves out the TLS port
// only when eBPF capture really runs. start then runs it.
type httpsCapture struct {
	// libraries are the TLS libraries captured.
	libraries ebpf.Libraries
	// standalone holds the loaded BPF programs when there is no NodeCollector
	// (standalone apidump); nil on the DaemonSet path, where the
	// NodeCollector loaded them for the node and buildHTTPSArgs chose the
	// pod's libraries.
	standalone *ebpf.Capture
}

// prepareHTTPSCapture returns the run's HTTPS capture, or nil when it does
// not run: HTTPS capture is off, or (standalone) the BPF programs cannot
// capture any of the libraries asked for. Call close on the result if start
// is never called.
func prepareHTTPSCapture(args *Args) *httpsCapture {
	if !args.HTTPS.Enabled {
		return nil
	}
	if args.HTTPS.NodeCollector != nil {
		return &httpsCapture{libraries: args.HTTPS.Libraries}
	}
	c, err := ebpf.Start(httpsLoadArgs(args))
	if err != nil {
		printer.Stderr.Warningf("HTTPS capture (eBPF) disabled: %v\n", err)
		return nil
	}
	return &httpsCapture{libraries: c.Libraries(), standalone: c}
}

// httpsLoadArgs returns the settings the BPF programs are loaded with.
func httpsLoadArgs(args *Args) ebpf.LoadArgs {
	load := ebpf.Defaults().LoadArgs
	load.MaxCaptureBytes = httpsBodyCap(args)
	load.EnforcePIDAllowlist = false
	load.EnableJava = args.HTTPS.Libraries.Java
	load.DisableOpenSSL = !args.HTTPS.Libraries.OpenSSL
	return load
}

func httpsBodyCap(args *Args) uint32 {
	if args.HTTPS.BodySizeCap == 0 {
		return 16384 // MAX_EVENT_PAYLOAD; see ebpf/programs/event.h
	}
	return args.HTTPS.BodySizeCap
}

// pcapFilters returns the pcap filters to use alongside h: when HTTPS
// capture runs (h is not nil), without the TLS port, so the libpcap path
// doesn't double-count handshake bytes already captured via eBPF. See
// docs/https-capture-design.md §6.1. Otherwise pcap keeps the port.
func (h *httpsCapture) pcapFilters(filters map[string]string, tlsPort uint16) map[string]string {
	if h == nil || tlsPort == 0 {
		return filters
	}
	printer.Stderr.Infof("HTTPS capture enabled: excluding TCP port %d from cBPF filter (pcap path).\n", tlsPort)
	// Negation filters intentionally untouched: if the user runs in
	// "capture everything else too" mode, the eBPF-captured plaintext flow is
	// the source of truth for the port, so the negation channel would still
	// want to see its *non-TLS* traffic (rare in practice). Override
	// behaviour gated behind the existing --bpf-filter knob for power users.
	return excludePortFromBPF(filters, tlsPort)
}

// close releases what prepareHTTPSCapture loaded, for a capture that is never
// started. It is safe on nil, and does nothing after start.
func (h *httpsCapture) close() {
	if h != nil && h.standalone != nil {
		h.standalone.Close()
	}
}

// start launches the eBPF HTTPS capture pipeline in its own goroutine and
// returns a stop function. The pipeline pushes
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
// `pool` is shared with the pcap pipeline so memview buffers are pooled
// consistently across both capture paths.
func (h *httpsCapture) start(
	ctx context.Context,
	args *Args,
	pool buffer_pool.BufferPool,
	collector trace.Collector,
	wg *sync.WaitGroup,
	tracker telemetry.Tracker,
	pod string,
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

	ebpfArgs := ebpf.Defaults().RunArgs
	ebpfArgs.DisableThermostat = args.HTTPS.DisableThermostat
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
			// The pod's JVMs get the Java agent's control file.
			JVMs: true,
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
				// JVMs get control files where Java capture is allowed: in
				// standalone apidump, its own netns (Capture.Run filters);
				// on the DaemonSet fallback, never (no pod netns).
				JVMs: true,
			})
		}
	}

	// The node's JVM attach counters, where the NodeCollector attaches.
	var jvmStats func() (jvm.AttachStats, bool)
	if args.HTTPS.NodeCollector != nil {
		jvmStats = args.HTTPS.NodeCollector.JVMStats
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
			httpsTelemetryWorker(captureCtx, 30*time.Second, ldr, therm, mgr, adapter, jvmStats, tracker, args.reportTelemetryCount, pod)
		}()
	}

	// Pump: read parsed traffic, hand to the collector chain.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if err := collector.Close(); err != nil {
				printer.Stderr.Warningf("ebpf: collector.Close: %v\n", err)
			}
		}()
		// The producer closes out after cancellation. Drain it rather than
		// returning on captureCtx.Done so already-adapted messages reach the
		// collector before its pair cache and report buffer are closed.
		for pnt := range out {
			if err := collector.Process(pnt); err != nil {
				printer.Stderr.Warningf("ebpf: collector.Process: %v\n", err)
			}
		}
	}()

	// Actual eBPF collect loop (libssl uprobes).
	//
	// Two paths:
	//  - NodeCollector set (DaemonSet): BPF programs already loaded once for the
	//    node. Subscribe registers this pod's discovery + out channel with the
	//    shared loader — no additional loader.Load() call.
	//  - NodeCollector nil (standalone apidump / tests): the programs
	//    prepareHTTPSCapture loaded run for this apidump alone.
	if args.HTTPS.NodeCollector != nil {
		unsubscribe, adapter := args.HTTPS.NodeCollector.Subscribe(
			captureCtx,
			ebpfArgs.Discovery,
			ebpfArgs.FactorySelector,
			out,
			ebpfArgs.ProcRoot,
			args.HTTPS.ContainerNetnsInode,
			// The attach outcome of the pod's JVMs.
			args.reportTelemetryCount,
		)
		// Expose node-level handles + this pod's adapter to the telemetry worker
		// (mirrors HookLoader). The adapter carries the per-pod MessagesEmitted /
		// FlowsActive counters, so passing it makes ebpf-stats msgs/flows_active
		// reflect the NodeCollector path instead of always reading 0.
		if ebpfArgs.HookLoader != nil {
			ebpfArgs.HookLoader(
				args.HTTPS.NodeCollector.Loader(),
				args.HTTPS.NodeCollector.Thermostat(),
				args.HTTPS.NodeCollector.Manager(),
				adapter,
			)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(out)
			<-captureCtx.Done()
			unsubscribe()
		}()
	} else {
		// Standalone path: run the programs prepareHTTPSCapture loaded.
		// Run closes them from now on, not close.
		c := h.standalone
		h.standalone = nil
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(out)
			if err := c.Run(captureCtx, ebpfArgs); err != nil {
				printer.Stderr.Warningf("ebpf: capture stopped: %v\n", err)
			}
		}()
	}

	return cancel
}
