package daemonset

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/version"
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

	d.Coverage.EvictTerminal(terminalTargetRetention)
	snapshot := d.Coverage.Snapshot()

	// rest.DaemonsetTelemetryRequest keeps its fields opaque to DaemonSet
	// implementation types, so CoverageStage keys are stringified here.
	stageCounts := make(map[string]int, len(snapshot.StageCounts))
	for stage, count := range snapshot.StageCounts {
		stageCounts[string(stage)] = count
	}

	// Degraded reflects problems the agent already knows about from the prior
	// interval: last heartbeat failed to deliver, or the coverage tracker is
	// dropping targets at capacity. "failed" is not reachable from here -- a
	// process that failed outright would not be sending this heartbeat at
	// all; that case is what heartbeat staleness (derived backend-side from
	// heartbeat age) exists to catch instead.
	wantState := rest.AgentStateHealthy
	if d.lastTelemetryFailed || snapshot.TruncatedTargets > 0 {
		wantState = rest.AgentStateDegraded
	}
	if wantState != d.agentState {
		d.agentState = wantState
		d.agentStateSince = time.Now().UTC()
	}
	agentStateSince := d.agentStateSince

	err := d.FrontClient.PostDaemonsetAgentTelemetry(ctx, rest.DaemonsetTelemetryRequest{
		Type:              rest.TelemetryTypeSnapshot,
		Event:             "agent_heartbeat",
		AgentID:           snapshot.AgentID,
		RunID:             snapshot.RunID,
		Sequence:          atomic.AddUint64(&d.telemetrySequence, 1),
		SchemaVersion:     "v1",
		KubernetesCluster: d.ClusterName,
		Environment:       d.InsightsEnvironment,
		AgentVersion:      version.ReleaseVersion().String(),
		GitVersion:        version.GitVersion(),
		AgentState:        d.agentState,
		AgentStateSince:   &agentStateSince,
		Targets:           snapshot.Targets,
		TruncatedTargets:  snapshot.TruncatedTargets,
		StageCounts:       stageCounts,
	})
	d.lastTelemetryFailed = err != nil
	if err != nil {
		printer.Errorf("Failed to send telemetry: %v\n", err)
	}

	// Flush counters regardless of the heartbeat result. Gating the flush on a
	// successful heartbeat means the counter window silently extends across
	// failures, and any counter describing delivery can then only ever be
	// recorded when delivery worked -- which makes it unable to report the
	// failure it exists to report.
	d.flushTelemetryEvents(snapshot)
}

func (d *Daemonset) recordTelemetryEvent(targetID, event string) {
	if event == "" {
		return
	}
	d.telemetryEventsMu.Lock()
	defer d.telemetryEventsMu.Unlock()
	if d.telemetryEvents == nil {
		d.telemetryEvents = make(map[string]map[string]uint64)
	}
	if d.telemetryEvents[event] == nil {
		d.telemetryEvents[event] = make(map[string]uint64)
	}
	d.telemetryEvents[event][targetID]++
}

func (d *Daemonset) flushTelemetryEvents(snapshot CoverageSnapshot) {
	windowEnd := time.Now().UTC()

	d.telemetryEventsMu.Lock()
	events := d.telemetryEvents
	windowStart := d.telemetryWindowStart
	d.telemetryEvents = make(map[string]map[string]uint64)
	d.telemetryWindowStart = windowEnd
	d.telemetryEventsMu.Unlock()

	// The window is reset above even when the sends below fail, so a delivery
	// failure loses one window of counters rather than silently merging it into
	// the next one. Dropping a window is visible via the sequence gap; a merged
	// window is not visible at all. Bounded local buffering with replay is
	// tracked separately as phase-3 work.
	for event, targets := range events {
		for targetID, count := range targets {
			ctx, cancel := context.WithTimeout(context.Background(), apiContextTimeout)
			err := d.FrontClient.PostDaemonsetAgentTelemetry(ctx, rest.DaemonsetTelemetryRequest{
				Type:              rest.TelemetryTypeEvents,
				Event:             event,
				AgentID:           snapshot.AgentID,
				RunID:             snapshot.RunID,
				Sequence:          atomic.AddUint64(&d.telemetrySequence, 1),
				SchemaVersion:     "v1",
				KubernetesCluster: d.ClusterName,
				Environment:       d.InsightsEnvironment,
				TargetID:          targetID,
				Count:             count,
				CounterType:       rest.CounterTypeIntervalDelta,
				WindowStart:       &windowStart,
				WindowEnd:         &windowEnd,
			})
			cancel()
			if err != nil {
				printer.Errorf("Failed to send telemetry event %q: %v\n", event, err)
			}
		}
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
	logf(" %-30v%-30v%-10v%-40v%-70v\n", "projectID", "currentState", "reproMode", "podUID", "podName")
	logf(hrBr)

	d.PodArgsByNameMap.Range(func(k, v interface{}) bool {
		podUID := k.(types.UID)
		podArgs := v.(*PodArgs)
		logf(" %-30v%-30v%-10v%-40v%-70v\n",
			podArgs.InsightsProjectID,
			podArgs.PodTrafficMonitorState,
			podArgs.ReproMode,
			podUID,
			podArgs.PodName,
		)
		return true
	})
	logf(hrBr)
}
