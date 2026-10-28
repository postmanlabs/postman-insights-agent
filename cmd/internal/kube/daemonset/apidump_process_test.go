package daemonset

import (
	"testing"
	"time"

	"github.com/postmanlabs/postman-insights-agent/rest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestStartApiDumpProcess_WorkspaceCooldownActive_EndsPodAsWorkspaceNotLinked(t *testing.T) {
	const workspaceID, systemEnv = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	key := rest.WorkspaceCooldownKey(workspaceID, systemEnv)
	rest.IngestCooldown.Mark(key, time.Hour)
	t.Cleanup(func() { rest.IngestCooldown.Clear(key) })

	podUID := types.UID("pod-2")
	podArgs := NewPodArgs("checkout-2")
	podArgs.WorkspaceID, podArgs.SystemEnv = workspaceID, systemEnv
	podArgs.PodTrafficMonitorState = PodRunning

	d := &Daemonset{Coverage: NewCoverageTracker("agent-1", 10)}
	d.Coverage.Observe(corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: podUID, Name: podArgs.PodName}}, CoveragePodConfigured, "configured", "")
	d.PodArgsByNameMap.Store(podUID, podArgs)

	if err := d.StartApiDumpProcess(podUID); err != nil {
		t.Fatalf("StartApiDumpProcess: %v", err)
	}
	if podArgs.PodTrafficMonitorState != TrafficMonitoringEnded {
		t.Fatalf("state = %s, want %s", podArgs.PodTrafficMonitorState, TrafficMonitoringEnded)
	}
	target := d.Coverage.Snapshot().Targets[0]
	if target.CurrentStage != CoveragePodStopped || target.Reason != "workspace_not_linked" {
		t.Fatalf("coverage = %s/%s, want %s/workspace_not_linked", target.CurrentStage, target.Reason, CoveragePodStopped)
	}
}
