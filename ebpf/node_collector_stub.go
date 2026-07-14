// SPDX-License-Identifier: Apache-2.0

//go:build !linux || !insights_bpf

package ebpf

// NodeCollector stub for non-Linux / non-insights_bpf builds.
// All methods are no-ops so callers compile without per-build-tag guards.

import (
	"context"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"

	"github.com/postmanlabs/postman-insights-agent/ebpf/discovery"
	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
	"github.com/postmanlabs/postman-insights-agent/ebpf/uprobes"
)

type NodeCollectorConfig struct {
	MaxCaptureBytes   uint32
	RateCapPerSec     uint32
	FlowIdleTimeout   time.Duration
	DisableThermostat bool
}

type NodeCollector struct{}

func NewNodeCollector(_ NodeCollectorConfig) (*NodeCollector, error) {
	return nil, ErrUnsupported
}

func (nc *NodeCollector) Close() error { return nil }

func (nc *NodeCollector) Run(_ context.Context) error { return ErrUnsupported }

func (nc *NodeCollector) Loader() *loader.Loader       { return nil }
func (nc *NodeCollector) Thermostat() *Thermostat      { return nil }
func (nc *NodeCollector) Manager() *uprobes.Manager    { return nil }

func (nc *NodeCollector) Subscribe(
	_ context.Context,
	_ <-chan discovery.Target,
	_ akinet.TCPParserFactorySelector,
	_ chan<- akinet.ParsedNetworkTraffic,
	_ string,
	_ uint64,
) (context.CancelFunc, *events.Adapter) {
	return func() {}, nil
}
