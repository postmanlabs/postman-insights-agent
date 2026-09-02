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

	// The counter map accumulated since the last flush rides along as
	// Events on this same heartbeat POST, instead of one HTTP request per
	// (event, target) pair -- 40 pods x ~6 events used to mean ~240 requests
	// per interval. drainTelemetryEvents resets the window unconditionally
	// (see its own comment), so a delivery failure below still drops exactly
	// one window's counters rather than silently growing the buffer forever.
	events := d.drainTelemetryEvents(time.Now().UTC())

	err := d.FrontClient.PostDaemonsetAgentTelemetry(ctx, rest.DaemonsetTelemetryRequest{
		Type:              rest.TelemetryTypeSnapshot,
		Event:             "agent_heartbeat",
		AgentID:           snapshot.AgentID,
		Sequence:          atomic.AddUint64(&d.telemetrySequence, 1),
		SchemaVersion:     "v1",
		KubernetesCluster: d.ClusterName,
		UserID:            d.InsightsUserID,
		TeamID:            d.InsightsTeamID,
		AgentVersion:      version.ReleaseVersion().String(),
		GitVersion:        version.GitVersion(),
		AgentState:        d.agentState,
		AgentStateSince:   &agentStateSince,
		Targets:           snapshot.Targets,
		TruncatedTargets:  snapshot.TruncatedTargets,
		StageCounts:       stageCounts,
		Events:            events,
	})
	d.lastTelemetryFailed = err != nil
	if err != nil {
		printer.Errorf("Failed to send telemetry: %v\n", err)
	}
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

// drainTelemetryEvents empties the in-memory counter buffer accumulated
// since the last flush and returns it as inline batch events for a
// caller to attach to whatever single request it is about to send (the
// periodic heartbeat, or the terminal agent_stopped event). The window is
// reset unconditionally, before the caller's POST is even attempted: gating
// the reset on a successful send would let the counter window silently
// extend across failures, and any counter describing delivery could then
// only ever be recorded when delivery worked -- unable to report the
// failure it exists to report. A dropped window is visible via the sequence
// gap; a silently merged one is not visible at all.
func (d *Daemonset) drainTelemetryEvents(windowEnd time.Time) []rest.DaemonsetTelemetryRequest {
	d.telemetryEventsMu.Lock()
	pending := d.telemetryEvents
	windowStart := d.telemetryWindowStart
	d.telemetryEvents = make(map[string]map[string]uint64)
	d.telemetryWindowStart = windowEnd
	d.telemetryEventsMu.Unlock()

	var events []rest.DaemonsetTelemetryRequest
	for event, targets := range pending {
		for targetID, count := range targets {
			// Best-effort as of drain time, not as of when each increment
			// happened: a target discovered mid-window resolves its service
			// partway through, so a window's total can end up attributed to
			// a service the target settled on only near the end of it. That
			// is the same imprecision StageCounts already has (a
			// point-in-time gauge, not a per-increment attribution), and
			// resolving it exactly would mean stamping identity on every
			// single recordTelemetryEvent call instead of once per window.
			serviceID, userID, teamID := d.Coverage.TargetIdentity(targetID)
			events = append(events, rest.DaemonsetTelemetryRequest{
				Type:        rest.TelemetryTypeEvents,
				Event:       event,
				TargetID:    targetID,
				ServiceID:   serviceID,
				UserID:      userID,
				TeamID:      teamID,
				Count:       count,
				CounterType: rest.CounterTypeIntervalDelta,
				WindowStart: &windowStart,
				WindowEnd:   &windowEnd,
			})
		}
	}
	return events
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
