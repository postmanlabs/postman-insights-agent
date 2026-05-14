// SPDX-License-Identifier: Apache-2.0
//
// kube_linux.go implements ebpf/discovery.NamespaceResolver against a real
// Kubernetes cluster, by combining:
//
//   - integrations/kube_apis.KubeClient — lists pods on the agent's node and
//     gives us each pod's metadata (namespace, UID).
//   - /host/proc/<pid>/cgroup           — extract the pod UID for any PID.
//
// The cgroup path on Kubernetes nodes looks like:
//
//     0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<UID>.slice/cri-containerd-<container_id>.scope
//
// (different runtimes vary the prefix slightly; we match on the pod UID
// segment, which is stable across containerd / cri-o / kind / GKE / EKS.)
//
// Build constraint: linux only — /proc layout and the kube client API are
// both Linux-only. Default builds get the stub.

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

	"github.com/postmanlabs/postman-insights-agent/integrations/kube_apis"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// podUIDFromCgroupRE matches the pod UID portion of a Kubernetes cgroup path.
// Pod UIDs are RFC 4122 UUIDs but Kubernetes normalises them by replacing
// dashes with underscores in some cgroup paths (the `_` form is used in
// systemd-managed cgroups).
var podUIDFromCgroupRE = regexp.MustCompile(`pod([0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12})`)

// KubeNamespaceResolver implements NamespaceResolver via the Kubernetes API
// and /proc. Safe for concurrent use.
type KubeNamespaceResolver struct {
	procRoot string // /host/proc in DaemonSet, /proc otherwise
	client   *kube_apis.KubeClient

	mu      sync.RWMutex
	uid2ns  map[string]string // pod UID (normalised, dashes) → namespace
	updated time.Time
}

// NewKubeNamespaceResolver builds a resolver. procRoot defaults to /proc;
// pass /host/proc when running as a DaemonSet with /proc bind-mounted.
//
// If a kube client can't be constructed (e.g. running outside a cluster), an
// error is returned and the caller can fall back to a nil NamespaceResolver
// (i.e. no namespace filtering — all libssl-loaded PIDs in scope).
func NewKubeNamespaceResolver(procRoot string) (*KubeNamespaceResolver, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	kc, err := kube_apis.NewKubeClient()
	if err != nil {
		return nil, fmt.Errorf("ebpf/discovery: kube client init: %w", err)
	}
	r := &KubeNamespaceResolver{
		procRoot: procRoot,
		client:   &kc,
		uid2ns:   map[string]string{},
	}
	// Prime the cache immediately so the first scan after Watch starts
	// already has data.
	if err := r.refresh(); err != nil {
		printer.Stderr.Warningf("ebpf/discovery: initial pod list failed: %v; will retry\n", err)
	}
	return r, nil
}

// Close releases the kube client.
func (r *KubeNamespaceResolver) Close() {
	if r.client != nil {
		r.client.Close()
	}
}

// Namespace returns the Kubernetes namespace for a PID, or "" if the PID
// isn't part of any pod on this node (host process, unknown pod, etc.).
func (r *KubeNamespaceResolver) Namespace(pid uint32) string {
	uid, err := r.podUIDForPID(pid)
	if err != nil || uid == "" {
		return ""
	}
	r.mu.RLock()
	ns := r.uid2ns[uid]
	r.mu.RUnlock()
	return ns
}

// RunRefresh polls the pod list every interval and updates the cache. Returns
// when ctx is cancelled.
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
				printer.Debugf("ebpf/discovery: pod refresh failed: %v\n", err)
			}
		}
	}
}

// refresh re-lists pods on the node and rebuilds the uid → ns map.
func (r *KubeNamespaceResolver) refresh() error {
	pods, err := r.client.GetPodsInAgentNode()
	if err != nil {
		return err
	}
	fresh := make(map[string]string, len(pods))
	for _, pod := range pods {
		// Pod UID is the canonical dash-separated form. We normalise the
		// cgroup-extracted UID to that form before lookup.
		fresh[string(pod.UID)] = pod.Namespace
	}

	r.mu.Lock()
	r.uid2ns = fresh
	r.updated = time.Now()
	r.mu.Unlock()
	return nil
}

// podUIDForPID reads /proc/<pid>/cgroup and extracts the pod UID, if any.
func (r *KubeNamespaceResolver) podUIDForPID(pid uint32) (string, error) {
	b, err := os.ReadFile(filepath.Join(r.procRoot, strconv.Itoa(int(pid)), "cgroup"))
	if err != nil {
		return "", err
	}
	m := podUIDFromCgroupRE.FindSubmatch(b)
	if m == nil {
		return "", nil
	}
	// Normalise underscores → dashes (kubelet uses `_` in systemd cgroup names).
	return strings.ReplaceAll(string(m[1]), "_", "-"), nil
}
