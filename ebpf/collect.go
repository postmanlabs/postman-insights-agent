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
// See docs/https-capture-design.md §5.2 for the architecture diagram and
// §9 (Phase 2) for the production integration plan.

package ebpf

import (
	"errors"

	"github.com/postmanlabs/postman-insights-agent/ebpf/discovery"
)

// DiscoveryChan is a typed alias so callers don't need to import the
// ebpf/discovery package directly when overriding Args.Discovery.
type DiscoveryChan = <-chan discovery.Target

// ErrUnsupported is returned by Collect on platforms / builds where the eBPF
// subsystem is unavailable.
var ErrUnsupported = errors.New("ebpf: HTTPS capture not supported on this platform/build")
