// SPDX-License-Identifier: Apache-2.0
//
// kube_linux.go implements ebpf/discovery.NamespaceResolver against a real
// Kubernetes cluster.
//
// Why this is harder than just reading /proc/<pid>/cgroup
// -------------------------------------------------------
// On modern container runtimes (containerd, CRI-O on K8s 1.24+), each pod
// runs in its own cgroup namespace. When the agent reads /proc/<pid>/cgroup
// for a process in a different cgroup namespace, the kernel returns paths
// relative to the *reader's* cgroup namespace — typically "0::/../..", with
// no pod-UID visible. This affects both kind dev clusters AND real K8s
// production nodes; it's not a kind-specific bug.
//
// Two patterns avoid the problem:
//   1. Run the agent in the root cgroup namespace (requires privileged +
//      explicit cgroup-ns escape; not portable across CNIs and security
//      contexts).
//   2. Use CRI to enumerate containers and their init PIDs, then bridge
//      across PID namespaces via the cgroup-namespace inode (which IS
//      stable across PID namespaces — children inherit the parent's
//      cgroup ns by default).
//
// We use pattern (2), which is what OBI, Datadog system-probe, and Falco
// all do. Specifically:
//
//   For each pod on the node:
//     - kube_apis tells us its K8s namespace.
//     - CRI tells us the container init PIDs (in the agent's PID namespace).
//     - readlink /proc/<init_pid>/ns/cgroup → "cgroup:[N]" gives us the
//       cgroup-namespace inode N.
//   Build map: cgroup_ns_inode → k8s_namespace.
//
//   For each BPF event PID X (root-namespace PID):
//     - readlink /host/proc/X/ns/cgroup → "cgroup:[N']" gives the cgroup
//       namespace inode of the target process. (The kernel doesn't depend
//       on the reader's namespace for ns/* symlink content — it's the
//       absolute inode.)
//     - Lookup namespace by N'.
//
// This works identically in kind and on real K8s.

//go:build linux

package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/postmanlabs/postman-insights-agent/integrations/cri_apis"
	"github.com/postmanlabs/postman-insights-agent/integrations/kube_apis"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// cgroupNsRE matches the inode in `cgroup:[N]` symlink targets.
var cgroupNsRE = regexp.MustCompile(`cgroup:\[(\d+)\]`)

// KubeNamespaceResolver implements NamespaceResolver via the Kubernetes API
// + CRI + cgroup-namespace inode matching. Safe for concurrent use.
type KubeNamespaceResolver struct {
	procRoot     string // /host/proc when running as a DaemonSet (BPF event PIDs)
	agentProc    string // /proc — agent's own view, used for CRI-reported init PIDs
	kubeClient   *kube_apis.KubeClient
	criClient    *cri_apis.CriClient

	mu        sync.RWMutex
	cgroup2ns map[uint64]string // cgroup-ns inode → k8s namespace
	updated   time.Time
}

// NewKubeNamespaceResolver builds a resolver.
//
//   procRoot      — /host/proc on a DaemonSet (where BPF-emitted root-ns
//                   PIDs live). Defaults to /proc when empty.
//   agentProcRoot — /proc (the agent's own view). CRI returns init PIDs in
//                   this namespace. Defaults to /proc when empty.
//
// Returns an error if either the kube client or CRI client can't be built —
// callers should fall back to nil NamespaceResolver (no filtering) in that
// case rather than dropping all traffic.
func NewKubeNamespaceResolver(procRoot, agentProcRoot string) (*KubeNamespaceResolver, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	if agentProcRoot == "" {
		agentProcRoot = "/proc"
	}
	kc, err := kube_apis.NewKubeClient()
	if err != nil {
		return nil, fmt.Errorf("ebpf/discovery: kube client init: %w", err)
	}
	cc, err := cri_apis.NewCRIClient()
	if err != nil {
		kc.Close()
		return nil, fmt.Errorf("ebpf/discovery: CRI client init: %w", err)
	}
	r := &KubeNamespaceResolver{
		procRoot:   procRoot,
		agentProc:  agentProcRoot,
		kubeClient: &kc,
		criClient:  cc,
		cgroup2ns:  map[uint64]string{},
	}
	if err := r.refresh(); err != nil {
		printer.Stderr.Warningf("ebpf/discovery: initial CRI+kube enumeration failed: %v; will retry\n", err)
	}
	return r, nil
}

// Close releases the kube client. CriClient has no Close; the underlying
// gRPC connection is reaped on process exit.
func (r *KubeNamespaceResolver) Close() {
	if r.kubeClient != nil {
		r.kubeClient.Close()
	}
}

// Namespace returns the Kubernetes namespace for a PID, or "" if the PID
// isn't part of any known pod on this node.
//
// The PID argument here is in the *agent's* PID namespace (the same one
// discovery walks via /proc and uprobes attach with). cgroup-namespace
// inodes are stable across PID namespaces — children inherit their parent's
// cgroup ns — so reading /proc/<agent_ns_pid>/ns/cgroup gives the same
// inode as /host/proc/<root_ns_pid>/ns/cgroup for the same process.
func (r *KubeNamespaceResolver) Namespace(pid uint32) string {
	cgIno, err := readCgroupNsInode(r.agentProc, pid)
	if err != nil {
		return ""
	}
	r.mu.RLock()
	ns := r.cgroup2ns[cgIno]
	r.mu.RUnlock()
	return ns
}

// RunRefresh polls every interval and updates the cache. Returns when
// stopCh is closed.
func (r *KubeNamespaceResolver) RunRefresh(stopCh <-chan struct{}, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-t.C:
			if err := r.refresh(); err != nil {
				printer.Debugf("ebpf/discovery: CRI+kube refresh failed: %v\n", err)
			}
		}
	}
}

// refresh rebuilds the cgroup_ns_inode → namespace map.
func (r *KubeNamespaceResolver) refresh() error {
	pods, err := r.kubeClient.GetPodsInAgentNode()
	if err != nil {
		return fmt.Errorf("list pods: %w", err)
	}

	fresh := map[uint64]string{}
	for _, pod := range pods {
		ns := pod.Namespace
		containerIDs, err := r.kubeClient.GetContainerUUIDs(pod)
		if err != nil {
			continue
		}
		for _, cid := range containerIDs {
			pid, err := r.criClient.GetContainerPID(cid)
			if err != nil || pid <= 0 {
				continue
			}
			ino, err := readCgroupNsInode(r.agentProc, uint32(pid))
			if err != nil {
				continue
			}
			fresh[ino] = ns
		}
	}

	r.mu.Lock()
	r.cgroup2ns = fresh
	r.updated = time.Now()
	r.mu.Unlock()
	if len(fresh) > 0 {
		printer.Debugf("ebpf/discovery: refreshed cgroup_ns→namespace map (%d containers)\n", len(fresh))
	}
	return nil
}

// readCgroupNsInode reads procRoot/<pid>/ns/cgroup as a symlink and parses
// the inode number from the target "cgroup:[N]".
func readCgroupNsInode(procRoot string, pid uint32) (uint64, error) {
	link := filepath.Join(procRoot, strconv.Itoa(int(pid)), "ns", "cgroup")
	target, err := os.Readlink(link)
	if err != nil {
		return 0, err
	}
	m := cgroupNsRE.FindStringSubmatch(target)
	if m == nil {
		return 0, fmt.Errorf("unexpected ns/cgroup target %q", target)
	}
	return strconv.ParseUint(m[1], 10, 64)
}

// CgroupNsMapSnapshot returns a copy of the current cgroup_ns_inode → namespace
// map. Exposed for diagnostics; not used in the hot path.
func (r *KubeNamespaceResolver) CgroupNsMapSnapshot() map[uint64]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[uint64]string, len(r.cgroup2ns))
	for k, v := range r.cgroup2ns {
		out[k] = v
	}
	return out
}

// silence unused-import linter when no calls remain
var _ = strings.Split
