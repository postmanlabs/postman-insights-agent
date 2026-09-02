package daemonset

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/postmanlabs/postman-insights-agent/trace"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestCoverageTrackerRecordsStableTransitions(t *testing.T) {
	tracker := NewCoverageTracker("agent-1", 10)
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api-abc", Namespace: "prod", UID: "uid-1"}}
	tracker.Observe(pod, CoveragePodDiscovered, "", "")
	tracker.Observe(pod, CoverageDiscoveryFilterPassed, "passed_filters", "prod/api")

	snapshot := tracker.Snapshot()
	if snapshot.AgentID != "agent-1" {
		t.Fatalf("snapshot identity = %+v", snapshot)
	}
	if len(snapshot.Targets) != 1 {
		t.Fatalf("target count = %d, want 1", len(snapshot.Targets))
	}
	target := snapshot.Targets[0]
	if target.CurrentStage != CoverageDiscoveryFilterPassed || target.ServiceNameHint != "prod/api" {
		t.Fatalf("target = %+v", target)
	}
	if len(target.Transitions) != 2 || target.Transitions[0].Stage != CoveragePodDiscovered {
		t.Fatalf("transitions = %+v", target.Transitions)
	}
}

func TestCoverageTrackerIsBounded(t *testing.T) {
	tracker := NewCoverageTracker("agent-1", 1)
	tracker.Observe(corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "uid-1"}}, CoveragePodDiscovered, "", "")
	tracker.Observe(corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "uid-2"}}, CoveragePodDiscovered, "", "")

	snapshot := tracker.Snapshot()
	if len(snapshot.Targets) != 1 || snapshot.TruncatedTargets != 1 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

// Re-observing the same stage and reason is a replay, not a transition. The
// informer replays its cache on registration and on every resync, so counting
// these would inflate the funnel's denominator.
func TestCoverageTrackerTreatsRepeatObservationAsReplay(t *testing.T) {
	tracker := NewCoverageTracker("agent-1", 10)
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "uid-1"}}

	if changed := tracker.Observe(pod, CoveragePodDiscovered, "", ""); !changed {
		t.Fatal("first observation reported no change")
	}
	if changed := tracker.Observe(pod, CoveragePodDiscovered, "", ""); changed {
		t.Fatal("replayed observation reported a change")
	}
	if changed := tracker.Observe(pod, CoveragePodConfigured, "configured", ""); !changed {
		t.Fatal("stage change reported no change")
	}
	// A new reason at the same stage is a real transition, not a replay.
	if changed := tracker.Observe(pod, CoveragePodConfigured, "reconfigured", ""); !changed {
		t.Fatal("reason change reported no change")
	}

	target := tracker.Snapshot().Targets[0]
	if len(target.Transitions) != 3 {
		t.Fatalf("transitions = %+v, want 3", target.Transitions)
	}
}

// The informer replays its cache on every resync, which re-fires
// CoveragePodDiscovered for pods it already knows about -- including ones
// that have long since advanced further. Observe must not let that replay
// regress an already-advanced target back to an earlier stage.
func TestCoverageTrackerIgnoresResyncRegression(t *testing.T) {
	tracker := NewCoverageTracker("agent-1", 10)
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "uid-1"}}

	tracker.Observe(pod, CoveragePodDiscovered, "", "")
	tracker.Observe(pod, CoveragePodConfigured, "configured", "")

	if changed := tracker.Observe(pod, CoveragePodDiscovered, "", ""); changed {
		t.Fatal("resync re-discovery reported a change")
	}

	target := tracker.Snapshot().Targets[0]
	if target.CurrentStage != CoveragePodConfigured {
		t.Fatalf("current_stage = %q, want pod_configured to survive the resync replay", target.CurrentStage)
	}
	if len(target.Transitions) != 2 {
		t.Fatalf("transitions = %+v, want the resync replay to add no new transition", target.Transitions)
	}

	// Terminal stages are exempt from the rank guard: a pod can fail from any
	// stage, and that is always a real fact worth recording.
	if changed := tracker.Observe(pod, CoveragePodFailed, "pod_phase_failed", ""); !changed {
		t.Fatal("terminal transition from a non-terminal stage reported no change")
	}
}

// StartProcessInExistingPods and handlePodAddEvent both re-walk every pod
// they already know about on each reconcile/resync, unconditionally
// re-observing CoveragePodConfigured -- even for a target that has already
// resolved its service via SetResolvedService (which runs inside the
// target's own capture goroutine, independently of the watcher's reconcile
// loop). The rank guard must reject that stale replay rather than regress an
// already-service_resolved target back to pod_configured.
func TestCoverageTrackerIgnoresPodConfiguredReplayAfterServiceResolved(t *testing.T) {
	tracker := NewCoverageTracker("agent-1", 10)
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "uid-1"}}

	tracker.Observe(pod, CoveragePodDiscovered, "", "")
	tracker.Observe(pod, CoveragePodConfigured, "configured", "")
	tracker.SetResolvedService("uid-1", "svc-1", "svc-name")

	// A later reconcile re-walks the pod and re-fires the same observation it
	// always does, unconditionally.
	if changed := tracker.Observe(pod, CoveragePodConfigured, "configured", ""); changed {
		t.Fatal("reconcile re-observing pod_configured reported a change")
	}

	target := tracker.Snapshot().Targets[0]
	if target.CurrentStage != CoverageServiceResolved {
		t.Fatalf("current_stage = %q, want service_resolved to survive the reconcile replay", target.CurrentStage)
	}
}

func TestCoverageTrackerConcurrentObserveAndSnapshot(t *testing.T) {
	tracker := NewCoverageTracker("agent-1", 100)
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "uid-1"}}
	var wg sync.WaitGroup
	var reason atomic.Int64
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				// Distinct reasons so every call is a real transition and the
				// per-target cap is what bounds the list.
				tracker.Observe(pod, CoverageCapturing, strconv.FormatInt(reason.Add(1), 10), "")
				_ = tracker.Snapshot()
			}
		}()
	}
	wg.Wait()
	if got := len(tracker.Snapshot().Targets[0].Transitions); got != maxCoverageTransitionsPerTarget {
		t.Fatalf("transition count = %d, want %d", got, maxCoverageTransitionsPerTarget)
	}
}

func TestCoverageTrackerReportsCaptureAndUploadLiveness(t *testing.T) {
	tracker := NewCoverageTracker("agent-1", 10)
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "uid-1"}}
	tracker.Observe(pod, CoveragePodDiscovered, "", "")

	// Before an apidump process exists there is no activity handle, so the
	// liveness fields must be absent rather than zero-valued.
	if target := tracker.Snapshot().Targets[0]; target.LastMessageAt != nil || target.LastUploadAt != nil {
		t.Fatalf("target reported liveness before capture started: %+v", target)
	}

	activity := &TargetActivity{}
	tracker.AttachActivity("uid-1", activity)

	pcapAt := time.Unix(1700000000, 0).UTC()
	ebpfAt := pcapAt.Add(time.Minute)
	activity.RecordPcapMessage(pcapAt)
	activity.RecordEBPFMessage(ebpfAt)
	tracker.RecordUpload("uid-1", ebpfAt, trace.UploadThrottled)

	target := tracker.Snapshot().Targets[0]
	if target.LastPcapMessageAt == nil || !target.LastPcapMessageAt.Equal(pcapAt) {
		t.Fatalf("last pcap message = %v, want %v", target.LastPcapMessageAt, pcapAt)
	}
	if target.LastEBPFMessageAt == nil || !target.LastEBPFMessageAt.Equal(ebpfAt) {
		t.Fatalf("last eBPF message = %v, want %v", target.LastEBPFMessageAt, ebpfAt)
	}
	// LastMessageAt is the later of the two pipelines.
	if target.LastMessageAt == nil || !target.LastMessageAt.Equal(ebpfAt) {
		t.Fatalf("last message = %v, want %v", target.LastMessageAt, ebpfAt)
	}
	if target.LastUploadStatus != trace.UploadThrottled {
		t.Fatalf("last upload status = %q, want %q", target.LastUploadStatus, trace.UploadThrottled)
	}
	if target.LastUploadAt == nil || !target.LastUploadAt.Equal(ebpfAt) {
		t.Fatalf("last upload at = %v, want %v", target.LastUploadAt, ebpfAt)
	}

	// The live handle must never leak into the serialized snapshot.
	if target.activity != nil {
		t.Fatal("snapshot leaked the activity handle")
	}
}

// Stages that mean "this pod will never be monitored" must be evictable.
// Such pods never enter PodArgsByNameMap, so handlePodDeleteEvent bails before
// it can mark them pod_stopped; if they are not terminal here, nothing ever
// removes them and each holds a maxTargets slot for the life of the process.
func TestEvictTerminalReclaimsNeverMonitoredTargets(t *testing.T) {
	cases := []struct {
		name   string
		stage  CoverageStage
		reason string
	}{
		{"filter_rejected", CoverageDiscoveryFilterRejected, "namespace_excluded"},
		{"config_failed", CoveragePodConfigurationFailed, "configuration_error"},
		{"pod_stopped", CoveragePodStopped, "terminated"},
		{"pod_failed", CoveragePodFailed, "pod_phase_failed"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tracker := NewCoverageTracker("agent-1", 2)
			pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "dead-1"}}
			tracker.Observe(pod, tc.stage, tc.reason, "")
			ageTarget(tracker, "dead-1", 2*time.Hour)

			tracker.EvictTerminalTargets(terminalRetention(DefaultTelemetryInterval))

			if got := len(tracker.Snapshot().Targets); got != 0 {
				t.Fatalf("target at %s survived eviction: %d remain", tc.stage, got)
			}
		})
	}
}

// In-flight stages must survive eviction however long they sit there: a pod
// mid-onboarding, or one capturing steadily, only refreshes ObservedAt when it
// transitions, so age alone does not mean it is finished.
func TestEvictTerminalKeepsInFlightTargets(t *testing.T) {
	for _, stage := range []CoverageStage{
		CoveragePodDiscovered,
		CoverageDiscoveryFilterPassed,
		CoveragePodConfigured,
		CoverageCapturing,
	} {
		t.Run(string(stage), func(t *testing.T) {
			tracker := NewCoverageTracker("agent-1", 2)
			tracker.Observe(corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "live-1"}}, stage, "", "")
			ageTarget(tracker, "live-1", 2*time.Hour)

			tracker.EvictTerminalTargets(terminalRetention(DefaultTelemetryInterval))

			if got := len(tracker.Snapshot().Targets); got != 1 {
				t.Fatalf("in-flight target at %s was evicted", stage)
			}
		})
	}
}

// The cap must be spendable on pods we actually monitor: a churn of rejected
// pods that fills it must not lock out a real target before the next
// heartbeat's EvictTerminalTargets gets a chance to run.
func TestObserveReclaimsTerminalSlotAtCap(t *testing.T) {
	tracker := NewCoverageTracker("agent-1", 3)
	for i := 0; i < 3; i++ {
		uid := "rejected-" + strconv.Itoa(i)
		tracker.Observe(
			corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: types.UID(uid)}},
			CoverageDiscoveryFilterRejected, "namespace_excluded", "",
		)
	}

	real := corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "real-1"}}
	if !tracker.Observe(real, CoveragePodDiscovered, "", "") {
		t.Fatal("real target rejected while finished ones held every slot")
	}
	if snap := tracker.Snapshot(); snap.TruncatedTargets != 0 {
		t.Fatalf("truncated %d real targets", snap.TruncatedTargets)
	}
}

// A cap held entirely by in-flight targets must still truncate -- reclamation
// is only ever allowed to take a slot from a finished target.
func TestObserveStillTruncatesWhenNothingIsTerminal(t *testing.T) {
	tracker := NewCoverageTracker("agent-1", 1)
	tracker.Observe(corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "live-1"}}, CoverageCapturing, "", "")

	if tracker.Observe(corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "new-1"}}, CoveragePodDiscovered, "", "") {
		t.Fatal("admitted a target by evicting a live one")
	}
	snap := tracker.Snapshot()
	if len(snap.Targets) != 1 || snap.TruncatedTargets != 1 {
		t.Fatalf("snapshot = %+v", snap)
	}
}

// Retention is derived from the heartbeat so a terminal target always spans at
// least one snapshot, with slack for ticker jitter, at any interval.
func TestTerminalTargetRetentionTracksHeartbeat(t *testing.T) {
	for _, hb := range []time.Duration{DefaultTelemetryInterval, DevelopmentTelemetryInterval} {
		if got := terminalRetention(hb); got <= hb {
			t.Fatalf("retention %v for heartbeat %v leaves no slack", got, hb)
		}
	}
	if got := terminalRetention(0); got <= 0 {
		t.Fatalf("retention %v for unset heartbeat", got)
	}
}

func ageTarget(t *CoverageTracker, uid string, by time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.targets[uid].ObservedAt = time.Now().UTC().Add(-by)
}
