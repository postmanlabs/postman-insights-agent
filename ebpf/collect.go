// Package ebpf is the entry point for the eBPF-based HTTPS capture subsystem.
//
// `Collect` mirrors the signature of `pcap.Collect`: it runs until `stop` is
// closed and pushes parsed HTTP requests and responses into a trace.Collector.
//
// The full lifecycle is:
//
//	loader.Load → discovery.Watch → uprobes.Manager.AttachLibSSL
//	                                    ↓
//	                          BPF ringbuf (kernel)
//	                                    ↓
//	                          events.Reader → events.Adapter
//	                                    ↓
//	                          akinet.ParsedNetworkTraffic
//	                                    ↓
//	                          trace.Collector.Process(...)
//
// See docs/https-capture-design.md §5.2 for the architecture diagram.

package ebpf

import (
	"errors"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"

	"github.com/postmanlabs/postman-insights-agent/ebpf/discovery"
	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
	"github.com/postmanlabs/postman-insights-agent/ebpf/uprobes"
)

// DiscoveryChan is a typed alias so callers don't need to import the
// ebpf/discovery package directly when overriding Args.Discovery.
type DiscoveryChan = <-chan discovery.Target

// ErrUnsupported is returned by Start and Collect on platforms / builds where
// the eBPF subsystem is unavailable.
var ErrUnsupported = errors.New("ebpf: HTTPS capture not supported on this platform/build")

// Args bundles configuration for Collect.
type Args struct {
	LoadArgs
	RunArgs
}

// LoadArgs are the settings Start loads the BPF programs with.
type LoadArgs struct {
	// MaxCaptureBytes is the per-event plaintext byte cap (forwarded to BPF).
	MaxCaptureBytes uint32

	// EnforcePIDAllowlist gates whether the BPF probe ignores PIDs not in the
	// target_pids map. When true, only PIDs discovered by the discovery
	// subsystem (auto-populated via /proc scanning) are captured; when false,
	// all TLS traffic is captured regardless of PID.
	EnforcePIDAllowlist bool

	// EnableJava also loads the Java TLS programs. Java capture is confined
	// to the agent's own network namespace: a sidecar's pod (even with
	// hostPID, where discovery sees the whole node), or the host's for an
	// agent on the host. Its frames are accepted, and its JVMs' control files
	// written, only there. With it off, those JVMs' control files say
	// disabled.
	EnableJava bool

	// DisableOpenSSL attaches no libssl uprobes, so only Java is captured.
	DisableOpenSSL bool
}

// Libraries returns the TLS libraries a asks for.
func (a LoadArgs) Libraries() Libraries {
	return Libraries{OpenSSL: !a.DisableOpenSSL, Java: a.EnableJava}
}

// RunArgs are the settings Run captures with.
type RunArgs struct {
	// DiscoveryInterval controls how often the agent re-scans /proc for new
	// PIDs that have libssl loaded.
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

	// DisableThermostat skips the CPU thermostat (§6.2 layer 5). Useful for
	// Kind e2e demos where background workloads would otherwise throttle
	// max_capture_bytes down to 64 and break HTTP parsing.
	DisableThermostat bool

	// ProcRoot is the path the resolver should treat as /proc. Default ""
	// resolves to /proc. DaemonSet deployments that bind-mount the kernel's
	// root /proc into the agent pod (typically at /host/proc) pass that here
	// so BPF-emitted root-namespace PIDs match /proc entries.
	ProcRoot string

	// Discovery is an optional pre-built discovery channel. When nil,
	// Run builds its own via discovery.WatchWith. Set this to use a
	// custom discovery source or pre-scoped namespace/netns filtering.
	Discovery DiscoveryChan

	// Loader observability: Thermostat / counter access is via the returned
	// Stats interface (see Stats()). Set HookLoader to receive the loader
	// handle for telemetry wiring; the lifecycle remains owned by Run.
	HookLoader func(*loader.Loader, *Thermostat, *uprobes.Manager, *events.Adapter)
}

// Defaults returns sensible default Args for production use.
func Defaults() Args {
	return Args{
		LoadArgs: LoadArgs{
			MaxCaptureBytes:     16384,
			EnforcePIDAllowlist: false,
		},
		RunArgs: RunArgs{
			DiscoveryInterval: 5 * time.Second,
			FlowIdleTimeout:   30 * time.Second,
		},
	}
}
