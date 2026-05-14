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
// akinet.ParsedNetworkTraffic into the *same* trace.Collector chain that
// pcap.Collect feeds, so downstream redaction / rate limit / backend ship
// logic is unchanged.
//
// On builds without `insights_bpf` (or non-Linux), ebpf.Collect returns
// ebpf.ErrUnsupported immediately; this function logs a warning and returns
// a no-op stop.
//
// `pool` is shared with the pcap pipeline so memview buffers are pooled
// consistently. `collector` is the same chain returned by the per-interface
// collector wiring in apidump.go (rate-limited, redacted, backend-bound).
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
	out := make(chan akinet.ParsedNetworkTraffic, 1024)

	// Same parser factories the pcap path uses. Note: TLS handshake parser
	// is intentionally NOT here \u2014 the eBPF path delivers post-decryption
	// bytes, so the bytes that arrive on `out` are already plaintext HTTP.
	factories := []akinet.TCPParserFactory{
		akihttp.NewHTTPRequestParserFactory(pool),
		akihttp.NewHTTPResponseParserFactory(pool),
	}
	selector := akinet.TCPParserFactorySelector(factories)

	bodyCap := args.HTTPSBodySizeCap
	if bodyCap == 0 {
		bodyCap = 1024
	}

	ebpfArgs := ebpf.Defaults()
	ebpfArgs.MaxCaptureBytes = bodyCap
	ebpfArgs.EnforcePIDAllowlist = false
	ebpfArgs.FactorySelector = selector
	ebpfArgs.Out = out
	ebpfArgs.RateCapPerSec = args.HTTPSRateCapPerSec

	// DaemonSet deployments bind-mount the kernel's root /proc to /host/proc.
	// When present, use it for resolver lookups so BPF-emitted root-ns PIDs
	// match /proc entries. Outside of DaemonSets, /proc is correct.
	if _, err := os.Stat("/host/proc/self"); err == nil {
		ebpfArgs.ProcRoot = "/host/proc"
	}

	// Namespace filtering. When --https-target-namespaces is set, build a
	// KubeNamespaceResolver and wire it into discovery.Watch via Args.Discovery.
	// If kube client init fails (e.g. running outside a cluster), warn and
	// fall back to no filtering — the user explicitly opted in to capture,
	// and silently dropping everything would be more surprising than the
	// fallback.
	if len(args.HTTPSTargetNamespaces) > 0 {
		procRoot := "/proc"
		if _, err := os.Stat("/host/proc/self"); err == nil {
			procRoot = "/host/proc"
		}
		// agentProcRoot is always /proc — that's the agent's own PID-namespace
		// view, which is where CRI-returned container init PIDs live.
		// procRoot is /host/proc on a DaemonSet (root-ns PIDs that BPF emits).
		resolver, err := discovery.NewKubeNamespaceResolver(procRoot, "/proc")
		if err != nil {
			printer.Stderr.Warningf(
				"ebpf: --https-target-namespaces set but kube client init failed (%v); "+
					"falling back to no namespace filtering.\n", err)
		} else {
			allowed := make(map[string]struct{}, len(args.HTTPSTargetNamespaces))
			for _, ns := range args.HTTPSTargetNamespaces {
				allowed[ns] = struct{}{}
			}
			printer.Stderr.Infof(
				"ebpf: namespace filtering enabled — allowed namespaces: %v\n",
				args.HTTPSTargetNamespaces)

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

	// Actual eBPF collect loop.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(out)
		if err := ebpf.Collect(captureCtx, ebpfArgs); err != nil {
			printer.Stderr.Warningf("ebpf: capture stopped: %v\n", err)
		}
	}()

	return cancel
}
