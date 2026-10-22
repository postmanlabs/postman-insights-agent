package daemonset

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/golang/mock/gomock"
	"github.com/postmanlabs/postman-insights-agent/rest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// A heartbeat interval with counters accumulated for multiple targets
// must produce exactly one HTTP POST, with the counters attached as Events
// on that same request -- not one POST per (event, target) pair.
func TestSendTelemetryBatchesCountersIntoOnePost(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockClient := rest.NewMockFrontClient(ctrl)

	d := &Daemonset{
		ClusterName:      "test-cluster",
		Coverage:         NewCoverageTracker("agent-1", 10),
		FrontClient:      mockClient,
		telemetryEnabled: true,
	}
	// Verbose, so the lifecycle events below are not filtered out; this test
	// is about batching, not the lean filter.
	d.verboseTelemetry.Store(true)
	d.recordTelemetryEvent("pod-a", "pod_discovered")
	d.recordTelemetryEvent("pod-b", "pod_discovered")
	d.recordTelemetryEvent("pod-a", "pod_configured")

	var captured rest.DaemonsetTelemetryRequest
	mockClient.EXPECT().
		PostDaemonsetAgentTelemetry(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ interface{}, req rest.DaemonsetTelemetryRequest) (rest.DaemonsetTelemetryResponse, error) {
			captured = req
			return rest.DaemonsetTelemetryResponse{}, nil
		}).
		Times(1)

	d.sendTelemetry()

	if captured.Event != "agent_heartbeat" {
		t.Fatalf("captured.Event = %q, want agent_heartbeat", captured.Event)
	}
	if len(captured.Events) != 3 {
		t.Fatalf("captured.Events = %+v, want 3 batched counter rows", captured.Events)
	}
	for _, event := range captured.Events {
		if event.Type != rest.TelemetryTypeEvents || event.CounterType != rest.CounterTypeIntervalDelta {
			t.Fatalf("event = %+v, want type=events counter_type=interval_delta", event)
		}
	}

	// The buffer must be drained: a second call with nothing newly recorded
	// sends no events.
	mockClient.EXPECT().
		PostDaemonsetAgentTelemetry(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ interface{}, req rest.DaemonsetTelemetryRequest) (rest.DaemonsetTelemetryResponse, error) {
			captured = req
			return rest.DaemonsetTelemetryResponse{}, nil
		}).
		Times(1)
	d.sendTelemetry()
	if len(captured.Events) != 0 {
		t.Fatalf("captured.Events = %+v, want the drained buffer to stay empty", captured.Events)
	}
}

// Lean drops the pod lifecycle events at drain time but keeps every drop
// counter, including apidump_start_failed.
func TestDrainTelemetryEventsLeanDropsLifecycleEvents(t *testing.T) {
	d := &Daemonset{Coverage: NewCoverageTracker("agent-1", 10), telemetryEnabled: true}
	d.recordTelemetryEvent("pod-a", "pod_discovered")
	d.recordTelemetryEvent("pod-a", "capture_started")
	d.recordTelemetryEvent("pod-a", "apidump_start_failed")
	d.recordTelemetryCount("pod-a", "pcap_witness_paired", 5)

	got := map[string]bool{}
	for _, event := range d.drainTelemetryEvents(time.Now().UTC(), false) {
		got[event.Event] = true
	}
	want := map[string]bool{"apidump_start_failed": true, "pcap_witness_paired": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("lean drained events = %v, want %v", got, want)
	}
}

// newHeartbeatTestDaemonset returns a Daemonset tracking one pod, with a mock
// client that captures every heartbeat it is sent.
func newHeartbeatTestDaemonset(t *testing.T) (*Daemonset, *rest.DaemonsetTelemetryRequest) {
	ctrl := gomock.NewController(t)
	mockClient := rest.NewMockFrontClient(ctrl)
	d := &Daemonset{
		ClusterName:      "test-cluster",
		Coverage:         NewCoverageTracker("agent-1", 10),
		FrontClient:      mockClient,
		telemetryEnabled: true,
	}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "pod-a", Name: "checkout"}}
	d.Coverage.Observe(pod, CoveragePodDiscovered, "", "")

	captured := &rest.DaemonsetTelemetryRequest{}
	mockClient.EXPECT().
		PostDaemonsetAgentTelemetry(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ interface{}, req rest.DaemonsetTelemetryRequest) (rest.DaemonsetTelemetryResponse, error) {
			*captured = req
			return rest.DaemonsetTelemetryResponse{}, errors.New("keep the mode under test")
		}).
		AnyTimes()
	return d, captured
}

func eventNames(events []rest.DaemonsetTelemetryRequest) map[string]bool {
	names := map[string]bool{}
	for _, event := range events {
		names[event.Event] = true
	}
	return names
}

// Lean leaves out Targets and StageCounts but keeps the agent-scope health
// fields; verbose sends everything.
func TestSendTelemetryHeartbeatFieldsByMode(t *testing.T) {
	d, captured := newHeartbeatTestDaemonset(t)

	d.sendTelemetry()
	if captured.Targets != nil || captured.StageCounts != nil {
		t.Fatalf("lean heartbeat targets=%v stage_counts=%v, want both omitted", captured.Targets, captured.StageCounts)
	}
	if captured.AgentState == "" || captured.AgentStateSince == nil {
		t.Fatalf("lean heartbeat agent_state=%q since=%v, want both present", captured.AgentState, captured.AgentStateSince)
	}

	d.verboseTelemetry.Store(true)
	d.sendTelemetry()
	if captured.Targets == nil || len(captured.StageCounts) == 0 {
		t.Fatalf("verbose heartbeat targets=%v stage_counts=%v, want both present", captured.Targets, captured.StageCounts)
	}
}

// The mode is applied when the heartbeat drains the window, not when an
// event is recorded: a lifecycle event recorded while lean still ships once
// the agent has flipped to verbose, and one recorded while verbose is dropped
// once it has flipped back to lean.
func TestSendTelemetryAppliesModeAtSendTime(t *testing.T) {
	d, captured := newHeartbeatTestDaemonset(t)

	d.recordTelemetryEvent("pod-a", "pod_discovered")
	d.verboseTelemetry.Store(true)
	d.sendTelemetry()
	if !eventNames(captured.Events)["pod_discovered"] {
		t.Fatalf("events = %+v, want pod_discovered recorded while lean to ship after the flip to verbose", captured.Events)
	}

	d.recordTelemetryEvent("pod-a", "pod_configured")
	d.verboseTelemetry.Store(false)
	d.sendTelemetry()
	if eventNames(captured.Events)["pod_configured"] {
		t.Fatalf("events = %+v, want pod_configured recorded while verbose dropped after the flip to lean", captured.Events)
	}
}

// A heartbeat response sets the mode; a failed heartbeat keeps the last one.
func TestSendTelemetryUpdatesModeFromResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockClient := rest.NewMockFrontClient(ctrl)
	d := &Daemonset{
		ClusterName:      "test-cluster",
		Coverage:         NewCoverageTracker("agent-1", 10),
		FrontClient:      mockClient,
		telemetryEnabled: true,
	}

	verboseResp := rest.DaemonsetTelemetryResponse{}
	verboseResp.Telemetry.Verbose = true
	mockClient.EXPECT().
		PostDaemonsetAgentTelemetry(gomock.Any(), gomock.Any()).
		Return(verboseResp, nil)
	d.sendTelemetry()
	if !d.verboseTelemetry.Load() {
		t.Fatalf("verbose = false after a verbose response, want true")
	}

	mockClient.EXPECT().
		PostDaemonsetAgentTelemetry(gomock.Any(), gomock.Any()).
		Return(rest.DaemonsetTelemetryResponse{}, errors.New("timeout"))
	d.sendTelemetry()
	if !d.verboseTelemetry.Load() {
		t.Fatalf("verbose = false after a failed heartbeat, want the last value kept")
	}
}

func TestRecordTelemetryCountAccumulatesDelta(t *testing.T) {
	d := &Daemonset{telemetryEnabled: true}
	d.recordTelemetryCount("pod-a", "pcap_packets_dropped", 17)
	d.recordTelemetryCount("pod-a", "pcap_packets_dropped", 25)
	d.recordTelemetryCount("pod-a", "pcap_packets_dropped", 0)

	if got := d.telemetryEvents["pcap_packets_dropped"]["pod-a"]; got != 42 {
		t.Fatalf("pcap drop count = %d, want 42", got)
	}
}

func TestLoggedServiceIDUsesResolvedServiceWhenProjectIDUnset(t *testing.T) {
	d := &Daemonset{Coverage: NewCoverageTracker("agent-1", 10)}
	podUID := types.UID("pod-workspace")
	podArgs := NewPodArgs("checkout")
	podArgs.WorkspaceID = "11111111-1111-1111-1111-111111111111"

	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: podUID, Name: "checkout"}}
	d.Coverage.Observe(pod, CoveragePodConfigured, "configured", "")
	// Discovery and workspace mode configure the pod with an empty project ID.
	// SetProjectInfo records that zero ID before LookupService runs.
	d.Coverage.SetProjectInfo(string(podUID), akid.String(podArgs.InsightsProjectID), podArgs.WorkspaceID)

	if got := d.loggedServiceID(podUID, podArgs); got != akid.String(akid.ServiceID{}) {
		t.Fatalf("before resolve, service ID = %q, want the unset project ID", got)
	}

	const resolved = "svc_resolvedServiceId000000"
	d.Coverage.SetResolvedService(string(podUID), resolved, "checkout")

	if got := d.loggedServiceID(podUID, podArgs); got != resolved {
		t.Fatalf("logged service ID = %q, want resolved %q", got, resolved)
	}
	if podArgs.InsightsProjectID != (akid.ServiceID{}) {
		t.Fatalf("InsightsProjectID = %s, want it to stay unset", podArgs.InsightsProjectID)
	}
}

func TestLoggedServiceIDKeepsConfiguredProjectID(t *testing.T) {
	projectID := akid.GenerateServiceID()
	podArgs := NewPodArgs("payments")
	podArgs.InsightsProjectID = projectID
	podUID := types.UID("pod-project")

	d := &Daemonset{}
	if got := d.loggedServiceID(podUID, podArgs); got != projectID.String() {
		t.Fatalf("logged service ID = %q, want configured %q", got, projectID.String())
	}

	d.Coverage = NewCoverageTracker("agent-1", 10)
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: podUID, Name: "payments"}}
	d.Coverage.Observe(pod, CoveragePodConfigured, "configured", "")
	d.Coverage.SetProjectInfo(string(podUID), projectID.String(), "")
	d.Coverage.SetResolvedService(string(podUID), projectID.String(), "payments")

	if got := d.loggedServiceID(podUID, podArgs); got != projectID.String() {
		t.Fatalf("logged service ID = %q, want configured %q", got, projectID.String())
	}
}

func TestRecordTelemetryCountSkipsWhenTelemetryDisabled(t *testing.T) {
	d := &Daemonset{}
	d.recordTelemetryCount("pod-a", "pcap_packets_dropped", 17)
	if d.telemetryEvents != nil {
		t.Fatalf("telemetryEvents = %+v, want nil when telemetry is disabled", d.telemetryEvents)
	}
}
