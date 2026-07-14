// SPDX-License-Identifier: Apache-2.0

package ebpf

// This file is intentionally build-tag-free so the routing logic (routeSub) is
// compiled and unit-tested on every platform, independent of the BPF loader.

import (
	"github.com/akitasoftware/akita-libs/akinet"

	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
)

// podSub holds per-pod state registered via NodeCollector.Subscribe.
type podSub struct {
	adapter *events.Adapter
	out     chan<- akinet.ParsedNetworkTraffic
}

// routeSub selects the subscriber for a BPF event.
//
// It routes primarily by the event's network-namespace inode (netnsInode),
// which is stable across PID namespaces. This is what makes capture work in
// nested environments (KIND / k3d / minikube --driver=docker): there the BPF
// program stamps events with the init-namespace TGID, which never matches the
// node-namespace PID that discovery registered, but both the event's netns and
// the pod's netns resolve to the same inode.
//
// It falls back to the PID map when the netns inode is unavailable (0) or has
// no registered subscriber — preserving the original behaviour on non-nested
// nodes where /host/proc is the init namespace and PIDs already match.
//
// Returns nil when no subscriber matches (the event is dropped).
func routeSub(byNetns map[uint64]*podSub, byPID map[uint32]*podSub, netnsInode uint64, pid uint32) *podSub {
	if netnsInode != 0 {
		if s := byNetns[netnsInode]; s != nil {
			return s
		}
	}
	return byPID[pid]
}
