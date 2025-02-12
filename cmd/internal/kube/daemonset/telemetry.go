package daemonset

import (
	"context"
	"time"

	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/spf13/viper"
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

func (d *Daemonset) dumpPodsApiDumpProcessState() {
	if !viper.GetBool("debug") {
		return
	}
	logf := printer.Debugf

	logf("========================================================\n")
	logf("Pods active and their states:\n")
	logf("%15v %15v %25v\n", "podName", "projectID", "currentState")
	logf("========================================================\n")

	d.PodArgsByNameMap.Range(func(_, v interface{}) bool {
		podArgs := v.(*PodArgs)
		logf("%15v %15v %25v\n", podArgs.PodName, podArgs.InsightsProjectID, podArgs.PodTrafficMonitorState)
		return true
	})
	logf("========================================================\n")
}
