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

// routeTable maps a routing key (netns inode or PID) to the subscribers
// registered under it, oldest first. Subscriptions can share a key: hostNetwork
// pods share the node's netns and PIDs, and a pod's capture can restart before
// the old subscription's cleanup has run. Events go to the newest subscriber,
// and a subscriber that leaves removes only its own entry, so the others keep
// receiving events whatever order they leave in.
type routeTable[K comparable] map[K][]*podSub

// add registers s under k. Adding the same subscriber twice is a no-op.
func (r routeTable[K]) add(k K, s *podSub) {
	for _, x := range r[k] {
		if x == s {
			return
		}
	}
	r[k] = append(r[k], s)
}

// remove unregisters s from k, leaving other subscribers under k in place.
func (r routeTable[K]) remove(k K, s *podSub) {
	subs := r[k]
	for i, x := range subs {
		if x == s {
			subs = append(subs[:i:i], subs[i+1:]...)
			break
		}
	}
	if len(subs) == 0 {
		delete(r, k)
	} else {
		r[k] = subs
	}
}

// get returns the newest subscriber under k, or nil.
func (r routeTable[K]) get(k K) *podSub {
	subs := r[k]
	if len(subs) == 0 {
		return nil
	}
	return subs[len(subs)-1]
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
func routeSub(byNetns routeTable[uint64], byPID routeTable[uint32], netnsInode uint64, pid uint32) *podSub {
	if netnsInode != 0 {
		if s := byNetns.get(netnsInode); s != nil {
			return s
		}
	}
	return byPID.get(pid)
}
