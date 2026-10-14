// SPDX-License-Identifier: Apache-2.0

//go:build !linux || !insights_bpf

package ebpf

import (
	"context"
)

// Thermostat is a no-op stub on non-eBPF builds so callers can keep referring
// to *ebpf.Thermostat in their telemetry plumbing.
type Thermostat struct{}

func (*Thermostat) CurrentCap() uint32  { return 0 }
func (*Thermostat) CPUPercent() float64 { return 0 }

// Capture is a stub on builds without eBPF: Start returns ErrUnsupported.
type Capture struct{}

func Start(_ LoadArgs) (*Capture, error) { return nil, ErrUnsupported }

func (*Capture) Libraries() Libraries                   { return Libraries{} }
func (*Capture) Close()                                 {}
func (*Capture) Run(_ context.Context, _ RunArgs) error { return ErrUnsupported }

// Collect is a no-op on platforms / builds without eBPF support.
func Collect(_ context.Context, _ Args) error { return ErrUnsupported }
