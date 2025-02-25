package daemonset

import (
	"context"
	"time"

	"github.com/postmanlabs/postman-insights-agent/printer"
	"k8s.io/apimachinery/pkg/types"
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

// dumpPodsApiDumpProcessState logs the current state of active pods.
// It prints a formatted table with the pod name, project ID, and current state for each pod.
func (d *Daemonset) dumpPodsApiDumpProcessState() {
	logf := printer.Infof

	const hrBr = "================================================================================" +
		"===========================================================================================\n"

	logf("Dumping pods api dump process state, time: %s\n", time.Now().UTC())

	logf(hrBr)
	logf(" %-30v%-30v%-40v%-70v\n", "projectID", "currentState", "podUID", "podName")
	logf(hrBr)

	d.PodArgsByNameMap.Range(func(k, v interface{}) bool {
		podUID := k.(types.UID)
		podArgs := v.(*PodArgs)
		logf(" %-30v%-30v%-40v%-70v\n",
			podArgs.InsightsProjectID,
			podArgs.PodTrafficMonitorState,
			podUID,
			podArgs.PodName,
		)
		return true
	})
	logf(hrBr)
}
