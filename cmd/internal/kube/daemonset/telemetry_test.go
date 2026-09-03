package daemonset

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/postmanlabs/postman-insights-agent/rest"
)

// A heartbeat interval with counters accumulated for multiple targets
// must produce exactly one HTTP POST, with the counters attached as Events
// on that same request -- not one POST per (event, target) pair.
func TestSendTelemetryBatchesCountersIntoOnePost(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockClient := rest.NewMockFrontClient(ctrl)

	d := &Daemonset{
		ClusterName: "test-cluster",
		Coverage:    NewCoverageTracker("agent-1", 10),
		FrontClient: mockClient,
	}
	d.recordTelemetryEvent("pod-a", "pod_discovered")
	d.recordTelemetryEvent("pod-b", "pod_discovered")
	d.recordTelemetryEvent("pod-a", "pod_configured")

	var captured rest.DaemonsetTelemetryRequest
	mockClient.EXPECT().
		PostDaemonsetAgentTelemetry(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ interface{}, req rest.DaemonsetTelemetryRequest) error {
			captured = req
			return nil
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
		DoAndReturn(func(_ interface{}, req rest.DaemonsetTelemetryRequest) error {
			captured = req
			return nil
		}).
		Times(1)
	d.sendTelemetry()
	if len(captured.Events) != 0 {
		t.Fatalf("captured.Events = %+v, want the drained buffer to stay empty", captured.Events)
	}
}

func TestRecordTelemetryCountAccumulatesDelta(t *testing.T) {
	d := &Daemonset{}
	d.recordTelemetryCount("pod-a", "pcap_packets_dropped", 17)
	d.recordTelemetryCount("pod-a", "pcap_packets_dropped", 25)
	d.recordTelemetryCount("pod-a", "pcap_packets_dropped", 0)

	if got := d.telemetryEvents["pcap_packets_dropped"]["pod-a"]; got != 42 {
		t.Fatalf("pcap drop count = %d, want 42", got)
	}
}
