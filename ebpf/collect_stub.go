// SPDX-License-Identifier: Apache-2.0

//go:build !linux || !insights_bpf

package ebpf

import (
	"context"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"

	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
	"github.com/postmanlabs/postman-insights-agent/ebpf/uprobes"
)

// Thermostat is a no-op stub on non-eBPF builds so callers can keep referring
// to *ebpf.Thermostat in their telemetry plumbing.
type Thermostat struct{}

func (*Thermostat) CurrentCap() uint32   { return 0 }
func (*Thermostat) CPUPercent() float64 { return 0 }

// Args is the platform-neutral declaration so callers can construct it
// without per-build-tag code. On stub builds Collect immediately returns
// ErrUnsupported.
type Args struct {
	MaxCaptureBytes     uint32
	EnforcePIDAllowlist bool
	DiscoveryInterval   time.Duration
	FlowIdleTimeout     time.Duration
	FactorySelector     akinet.TCPParserFactorySelector
	Out                 chan<- akinet.ParsedNetworkTraffic
	Discovery           DiscoveryChan
	HookLoader          func(*loader.Loader, *Thermostat, *uprobes.Manager, *events.Adapter)
}

func Defaults() Args {
	return Args{
		MaxCaptureBytes:   1024,
		DiscoveryInterval: 5 * time.Second,
		FlowIdleTimeout:   30 * time.Second,
	}
}

// Collect is a no-op on platforms / builds without eBPF support.
func Collect(_ context.Context, _ Args) error { return ErrUnsupported }
