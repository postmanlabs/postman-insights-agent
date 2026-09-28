package daemonset

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/postmanlabs/postman-insights-agent/rest"
)

func TestPostDaemonsetEventSkipsWhenDisabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := rest.NewMockFrontClient(ctrl)
	var sequence uint64

	postDaemonsetEvent(false, client, &sequence, rest.DaemonsetTelemetryRequest{
		Event:             "agent_started",
		AgentID:           "agent-1",
		KubernetesCluster: "prod",
	})
	if sequence != 0 {
		t.Fatalf("sequence = %d, want 0", sequence)
	}
}

func TestPostDaemonsetEventSendsWhenEnabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := rest.NewMockFrontClient(ctrl)
	var sequence uint64
	var captured rest.DaemonsetTelemetryRequest
	client.EXPECT().
		PostDaemonsetAgentTelemetry(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ interface{}, req rest.DaemonsetTelemetryRequest) error {
			captured = req
			return nil
		})

	postDaemonsetEvent(true, client, &sequence, rest.DaemonsetTelemetryRequest{
		Event:             "agent_failed",
		AgentID:           "agent-1",
		KubernetesCluster: "prod",
		FailureCategory:   "cri_client_init_failed",
	})

	if sequence != 1 || captured.Sequence != 1 {
		t.Fatalf("sequence = %d captured = %d", sequence, captured.Sequence)
	}
	if captured.Event != "agent_failed" || captured.Type != rest.TelemetryTypeEvents {
		t.Fatalf("captured = %+v", captured)
	}
	if captured.SchemaVersion != "v1" || captured.FailureCategory != "cri_client_init_failed" {
		t.Fatalf("captured = %+v", captured)
	}
}
