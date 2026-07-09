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
	RateCapPerSec       uint32
	ProcRoot            string
	DisableThermostat   bool
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

// JavaTLSCollector is a stub on non-eBPF builds. The real implementation
// lives in collect_javatls_linux.go (//go:build linux && insights_bpf).
type JavaTLSCollector struct{}

func NewJavaTLSCollector(_ uint32, _ bool, _ *events.Adapter) (*JavaTLSCollector, error) {
	return nil, ErrUnsupported
}

func (c *JavaTLSCollector) Attach() error                              { return ErrUnsupported }
func (c *JavaTLSCollector) Run(_ context.Context, _ time.Time)        {}
func (c *JavaTLSCollector) Close() error                              { return nil }
func (c *JavaTLSCollector) AddTargetPID(_ uint32) error               { return nil }
func (c *JavaTLSCollector) RemoveTargetPID(_ uint32) error            { return nil }
func (c *JavaTLSCollector) CounterEmitted() uint64                    { return 0 }
func (c *JavaTLSCollector) CounterRingbufDrops() uint64               { return 0 }
func (c *JavaTLSCollector) CounterReadFailed() uint64                 { return 0 }
func (c *JavaTLSCollector) CounterBytes() uint64                      { return 0 }
func (c *JavaTLSCollector) CounterBadCmd() uint64                     { return 0 }
