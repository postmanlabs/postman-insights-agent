// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package discovery

import (
	"errors"
	"time"
)

// KubeNamespaceResolver is a stub for non-Linux builds. The real implementation
// lives in kube_linux.go and requires kernel namespaces + CRI APIs.
type KubeNamespaceResolver struct{}

// NewKubeNamespaceResolver always returns an error on non-Linux platforms.
// The caller (ebpf_integration.go) treats this as "kube client init failed"
// and falls back to no namespace filtering, which is the right behaviour on
// platforms where the eBPF subsystem itself is also unavailable.
func NewKubeNamespaceResolver(procRoot, agentProcRoot string) (*KubeNamespaceResolver, error) {
	return nil, errors.New("KubeNamespaceResolver is not supported on this platform")
}

func (r *KubeNamespaceResolver) Namespace(_ uint32) string { return "" }
func (r *KubeNamespaceResolver) Close()                    {}
func (r *KubeNamespaceResolver) RunRefresh(_ <-chan struct{}, _ time.Duration) {}
