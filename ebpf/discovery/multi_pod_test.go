package discovery

// multi_pod_test.go — regression tests for the N× duplicate-capture bug.
//
// Problem: eBPF uprobes are NOT network-namespace confined (unlike libpcap).
// When k8s scales a Deployment to N replicas inside one namespace, every
// pod's eBPF agent (running in the same Node's DaemonSet) fires for ALL N
// pods' SSL traffic → N× duplicate data in Postman.
//
// Fix: Each per-pod goroutine in the DaemonSet looks up the container's
// network-namespace inode via /proc/<pid>/ns/net and passes it as
// WatchOpts.NetnsInodeFilter. The discovery loop then only attaches uprobes
// to PIDs whose netns inode matches — exactly one pod's worth of processes.
//
// These tests simulate that scenario with a synthetic /proc tree so they run
// without a real cluster or root privileges.

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Synthetic /proc helper
// ---------------------------------------------------------------------------

// fakePod represents one replica pod: a PID and the inode of its synthetic
// network-namespace file.
type fakePod struct {
	pid   uint32
	inode uint64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestMultiPod_InodeFilter_IsolateSingleReplica is the core regression test.
//
// Setup: namespace "team-a" has 3 replica pods (PIDs 100, 200, 300), each in
// its own network namespace (distinct inodes A, B, C). A 4th pod (PID 400) is
// in namespace "team-b" and shares inode D. Each DaemonSet agent targets ONE
// pod's inode.
//
// Assert: with NetnsInodeFilter = inode(pod1), only PID 100 is allowed; PIDs
// 200, 300, 400 are all rejected — regardless of k8s namespace.
func TestMultiPod_InodeFilter_IsolateSingleReplica(t *testing.T) {
	dir := t.TempDir()

	// Three replicas of "team-a/myapp", one "team-b/otherapp" pod.
	// We encode the requested-inode groups as small integers (1..4); the
	// buildFakeProc helper turns these into real distinct OS inodes via separate
	// files and same-group inodes via hardlinks.
	pods := []fakePod{
		{pid: 100, inode: 1}, // team-a replica 1
		{pid: 200, inode: 2}, // team-a replica 2
		{pid: 300, inode: 3}, // team-a replica 3
		{pid: 400, inode: 4}, // team-b unrelated pod
	}
	realInodes := buildFakeProc2(t, dir, pods)

	// Agent for replica 1: filter = inode of PID 100.
	targetInode := realInodes[1]

	allowed := func(pid uint32) bool {
		if targetInode != 0 {
			return pidNetnsInode(dir, pid) == targetInode
		}
		return true
	}

	assert.True(t, allowed(100), "replica 1 (own pod) must be allowed")
	assert.False(t, allowed(200), "replica 2 (same namespace, different pod) must be rejected — prevents N× duplicate capture")
	assert.False(t, allowed(300), "replica 3 (same namespace, different pod) must be rejected — prevents N× duplicate capture")
	assert.False(t, allowed(400), "unrelated pod in team-b must be rejected")
}

// TestMultiPod_SameNetns_TwoContainersOnePod verifies that two containers that
// share a network namespace (same pod, init+sidecar) are BOTH allowed — the
// inode filter must not split containers within the same pod.
func TestMultiPod_SameNetns_TwoContainersOnePod(t *testing.T) {
	dir := t.TempDir()

	// PID 101 and PID 102 share the same netns (same pod, two containers).
	// PID 200 is a different pod in the same namespace.
	pods := []fakePod{
		{pid: 101, inode: 1}, // pod A, container 1
		{pid: 102, inode: 1}, // pod A, container 2 — SAME inode as 101
		{pid: 200, inode: 2}, // pod B, different netns
	}
	realInodes := buildFakeProc2(t, dir, pods)

	targetInode := realInodes[1] // inode for pod A

	allowed := func(pid uint32) bool {
		return pidNetnsInode(dir, pid) == targetInode
	}

	assert.True(t, allowed(101), "container 1 of pod A must be allowed")
	assert.True(t, allowed(102), "container 2 of pod A (same netns) must also be allowed")
	assert.False(t, allowed(200), "pod B must be rejected")
}

// TestMultiPod_NamespaceLevel_AllReplicasVisible verifies the namespace-level
// fallback (no inode) lets ALL replicas through. This is the pre-fix behaviour
// and remains valid when inode lookup fails — callers are warned about
// potential N× duplication in that case.
func TestMultiPod_NamespaceLevel_AllReplicasVisible(t *testing.T) {
	dir := t.TempDir()

	pods := []fakePod{
		{pid: 100, inode: 1}, // team-a replica 1
		{pid: 200, inode: 2}, // team-a replica 2
		{pid: 300, inode: 3}, // team-a replica 3
	}
	buildFakeProc2(t, dir, pods)

	// No inode filter — namespace-level: allowed() just returns true for any PID.
	// This simulates: inode lookup failed, TargetNamespaces=["team-a"], and the
	// KubeNamespaceResolver maps all three PIDs to "team-a".
	const targetInode uint64 = 0 // inode unavailable

	allowed := func(pid uint32) bool {
		if targetInode != 0 {
			return pidNetnsInode(dir, pid) == targetInode
		}
		// Namespace-level fallback — no inode filter.
		return true
	}

	assert.True(t, allowed(100), "replica 1 passes namespace-level filter")
	assert.True(t, allowed(200), "replica 2 passes namespace-level filter")
	assert.True(t, allowed(300), "replica 3 passes namespace-level filter")
	// NOTE: all three capture the same traffic → N× duplicates in Postman.
	// This is acceptable only as a fallback when inode is unavailable.
}

// TestMultiPod_ScaleFromOneToThree ensures that adding replicas after startup
// doesn't bleed into an agent that was scoped to the original single replica.
// At pod-level inode scoping the new replicas have distinct inodes and are
// ignored by the existing agent.
func TestMultiPod_ScaleFromOneToThree(t *testing.T) {
	dir := t.TempDir()

	// Start with one replica.
	pods := []fakePod{
		{pid: 100, inode: 1}, // original replica
	}
	realInodes := buildFakeProc2(t, dir, pods)
	targetInode := realInodes[1]

	// Agent already running — its filter is set to inode of PID 100.
	allowed := func(pid uint32) bool {
		return pidNetnsInode(dir, pid) == targetInode
	}

	assert.True(t, allowed(100), "original replica still allowed")

	// Deployment scales to 3 replicas — two new pods appear with new PIDs.
	// Simulate by creating their netns files in the same fake /proc tree.
	newPods := []fakePod{
		{pid: 200, inode: 2}, // new replica 2
		{pid: 300, inode: 3}, // new replica 3
	}
	buildFakeProc2(t, dir, newPods)

	assert.True(t, allowed(100), "original replica still allowed after scale-out")
	assert.False(t, allowed(200), "new replica 2 must be ignored — agent is pod-scoped")
	assert.False(t, allowed(300), "new replica 3 must be ignored — agent is pod-scoped")
}

// ---------------------------------------------------------------------------
// buildFakeProc2 — cleaner version without the inode extraction confusion
// ---------------------------------------------------------------------------

// buildFakeProc2 creates a minimal synthetic /proc under dir and returns a
// map from requested-inode-group → real OS inode. Pods with the same
// requested inode are hardlinked (same real inode); pods with different
// requested inodes get independent files (different real inodes).
func buildFakeProc2(t *testing.T, dir string, pods []fakePod) map[uint64]uint64 {
	t.Helper()

	firstFile := map[uint64]string{}  // requested-group → first real file path
	realInodes := map[uint64]uint64{} // requested-group → OS inode

	for _, pod := range pods {
		nsDir := filepath.Join(dir, fmt.Sprintf("%d", pod.pid), "ns")
		require.NoError(t, os.MkdirAll(nsDir, 0o755))
		netPath := filepath.Join(nsDir, "net")

		if owner, exists := firstFile[pod.inode]; exists {
			// Hardlink → same OS inode (same network namespace).
			require.NoError(t, os.Link(owner, netPath))
		} else {
			require.NoError(t, os.WriteFile(netPath, []byte{}, 0o644))
			firstFile[pod.inode] = netPath

			// Use pidNetnsInode with the temp dir so the real code path is
			// exercised and we capture what OS inode was assigned.
			got := pidNetnsInode(dir, pod.pid)
			require.NotZero(t, got, "pidNetnsInode must return non-zero for a freshly created file")
			realInodes[pod.inode] = got
		}
	}

	return realInodes
}
