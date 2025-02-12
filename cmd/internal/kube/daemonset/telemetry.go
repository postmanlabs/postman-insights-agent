package daemonset

import (
	"context"
	"time"

	"github.com/postmanlabs/postman-insights-agent/printer"
)

func (d *Daemonset) sendTelemetry() {
	printer.Debugf("Sending telemetry, time: %s", time.Now().UTC())

	ctx, cancel := context.WithTimeout(context.Background(), apiContextTimeout)
	defer cancel()

	err := d.FrontClient.PostDaemonsetAgentTelemetry(ctx, d.ClusterName)
	if err != nil {
		printer.Errorf("Failed to send telemetry: %v\n", err)
	}
}
