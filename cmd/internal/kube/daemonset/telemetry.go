package daemonset

import (
	"context"
	"time"

	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/spf13/viper"
)

// sendTelemetry sends telemetry data for the Daemonset.
// It logs the current time when telemetry is being sent and creates a context with a timeout.
// The telemetry data is sent using the FrontClient's PostDaemonsetAgentTelemetry method.
// If there is an error during the process, it logs the error.
func (d *Daemonset) sendTelemetry() {
	printer.Debugf("Sending telemetry, time: %s\n", time.Now().UTC())

	ctx, cancel := context.WithTimeout(context.Background(), apiContextTimeout)
	defer cancel()

	err := d.FrontClient.PostDaemonsetAgentTelemetry(ctx, d.ClusterName)
	if err != nil {
		printer.Errorf("Failed to send telemetry: %v\n", err)
	}
}

// dumpPodsApiDumpProcessState logs the current state of active pods if the debug mode is enabled.
// It prints a formatted table with the pod name, project ID, and current state for each pod.
func (d *Daemonset) dumpPodsApiDumpProcessState() {
	if !viper.GetBool("debug") {
		return
	}
	logf := printer.Debugf

	logf("Dumping pods api dump process state, time: %s\n", time.Now().UTC())

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
