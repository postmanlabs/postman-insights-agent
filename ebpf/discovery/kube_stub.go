// SPDX-License-Identifier: Apache-2.0
//
//go:build !linux
// +build !linux

// Non-Linux stub for KubeNamespaceResolver so the codebase compiles on
// macOS dev machines. Real implementation in kube_linux.go.

package discovery

import (
	"errors"
	"time"
)

// KubeNamespaceResolver is a stub on non-Linux platforms.
type KubeNamespaceResolver struct{}

// NewKubeNamespaceResolver returns an error on non-Linux platforms; eBPF
// HTTPS capture is Linux-only.
func NewKubeNamespaceResolver(procRoot, agentProcRoot string) (*KubeNamespaceResolver, error) {
	return nil, errors.New("KubeNamespaceResolver is only supported on Linux")
}

// Namespace is unreachable on non-Linux; the NamespaceResolver interface
// is satisfied so call sites compile.
func (r *KubeNamespaceResolver) Namespace(pid uint32) string { return "" }

// RunRefresh is a no-op on non-Linux. The signature matches the Linux
// implementation so call sites compile.
func (r *KubeNamespaceResolver) RunRefresh(stopCh <-chan struct{}, interval time.Duration) {
}

// Close is a no-op on non-Linux.
func (r *KubeNamespaceResolver) Close() error { return nil }
