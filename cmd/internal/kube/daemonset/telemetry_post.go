package daemonset

import (
	"context"
	"sync/atomic"

	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
)

// postDaemonsetEvent sends one agent-scope telemetry event.
// It does nothing when telemetry is disabled or the cluster name is empty.
func postDaemonsetEvent(
	enabled bool,
	client rest.FrontClient,
	sequence *uint64,
	req rest.DaemonsetTelemetryRequest,
) {
	if !enabled || req.KubernetesCluster == "" || client == nil {
		return
	}
	req.Type = rest.TelemetryTypeEvents
	req.SchemaVersion = "v1"
	req.Sequence = atomic.AddUint64(sequence, 1)

	ctx, cancel := context.WithTimeout(context.Background(), apiContextTimeout)
	defer cancel()
	err := client.PostDaemonsetAgentTelemetry(ctx, req)
	if err != nil {
		printer.Errorf("Failed to send %s telemetry: %v\n", req.Event, err)
		if req.Event == "agent_started" {
			printer.Infof(
				"Agent will try to send telemetry again, if the error still persists, agent " +
					"will not be tracked on our end, and it will not appear in the app's list of " +
					"clusters where the agent is running.\n",
			)
		}
	}
}

func (d *Daemonset) postEvent(req rest.DaemonsetTelemetryRequest) {
	req.AgentID = d.AgentID
	req.KubernetesCluster = d.ClusterName
	req.UserID = d.InsightsUserID
	req.TeamID = d.InsightsTeamID
	postDaemonsetEvent(d.telemetryEnabled, d.FrontClient, &d.telemetrySequence, req)
}
