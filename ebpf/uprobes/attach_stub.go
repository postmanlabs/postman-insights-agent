// SPDX-License-Identifier: Apache-2.0

//go:build !linux || !insights_bpf

package uprobes

import (
	"errors"

	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
)

// ErrUnsupported is returned by all Manager methods on stub builds.
var ErrUnsupported = errors.New("uprobes: not compiled into this binary (build with -tags insights_bpf on Linux)")

// Manager is a no-op stub on non-eBPF builds.
type Manager struct{}

func NewManager(_ *loader.Loader) *Manager { return &Manager{} }

func (*Manager) AttachLibSSL(_ uint32, _ string) error { return ErrUnsupported }
func (*Manager) Detach(_ uint32) error                  { return nil }
func (*Manager) Close() error                           { return nil }
func (*Manager) AttachedPIDs() []uint32                 { return nil }
