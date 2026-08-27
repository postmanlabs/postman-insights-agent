package daemonset

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/trace"
	corev1 "k8s.io/api/core/v1"
)

// CoverageStage is a stable point in the DaemonSet capture lifecycle.
type CoverageStage string

const (
	// CoveragePodDiscovered fires for every pod the watcher sees, in both
	// Workspace and Discovery Mode -- it is the funnel's mode-agnostic
	// denominator, not a Discovery Mode concept, despite the word "discovery"
	// elsewhere in this file meaning something narrower (see below).
	CoveragePodDiscovered CoverageStage = "pod_discovered"

	// CoverageDiscoveryFilterPassed and CoverageDiscoveryFilterRejected only
	// ever occur when `DiscoveryMode && PodFilter != nil` -- Workspace Mode has
	// no filter to evaluate, so these two are structurally absent there, not
	// failing silently. They replace the single CoverageEligible stage, which
	// used to share one `current_stage` value between "passed" and "rejected"
	// outcomes; that conflation made a rejected pod count toward the same
	// funnel gauge as a passed one (D3 in the events matrix).
	CoverageDiscoveryFilterPassed   CoverageStage = "discovery_filter_passed"
	CoverageDiscoveryFilterRejected CoverageStage = "discovery_filter_rejected"

	// CoveragePodAlreadyInstrumented was the "this pod already has the agent
	// sidecar, so the daemonset defers to it" coverage stage. Removed (D16):
	// this daemonset is never deployed alongside a sidecar agent, and the two
	// watch paths that could reach this case (this file's caller and
	// StartProcessInExistingPods) disagreed on when they'd observe a
	// sidecar-bearing pod, so the count was unstable rather than a real
	// signal. The sidecar-container filter itself is unchanged -- pods with
	// the agent sidecar are still skipped -- it's just no longer reported as
	// a coverage stage/event.

	// CoveragePodConfigured is the successful `inspectPodForEnvVars` outcome.
	CoveragePodConfigured CoverageStage = "pod_configured"

	// CoveragePodConfigurationFailed is the failed `inspectPodForEnvVars`
	// outcome. Split out from CoveragePodConfigured (D3): the two used to share
	// one stage/event distinguished only by `reason`, the same pass/reject
	// conflation already fixed for the discovery-filter case via
	// CoverageDiscoveryFilterPassed/CoverageDiscoveryFilterRejected. A shared
	// stage let a failed configuration inflate the same funnel gauge as a
	// successful one.
	CoveragePodConfigurationFailed CoverageStage = "pod_configuration_failed"

	CoverageServiceResolved CoverageStage = "service_resolved"
	CoverageApidumpStarted  CoverageStage = "apidump_started"
	CoverageCapturing       CoverageStage = "capturing"
	CoverageUploading       CoverageStage = "uploading"

	// CoveragePodStopped is a terminal, expected end to a target's lifecycle:
	// the pod was deleted or completed on its own (PodSucceeded/PodTerminated).
	// Kept distinct from CoveragePodFailed so a normal rollout/reschedule does
	// not read as a failure on the coverage dashboard.
	CoveragePodStopped CoverageStage = "pod_stopped"

	// CoveragePodFailed is a terminal, unrecoverable end to a target's
	// lifecycle, reached two ways: the pod itself was reported PodFailed by
	// Kubernetes at deletion time, or the in-process apidump goroutine for a
	// still-running pod panicked or returned an error (see the StopChan defer
	// in apidump_process.go). The second case is why this cannot simply be
	// folded into CoveragePodStopped -- the pod can still be alive in the
	// cluster while its capture process has died.
	CoveragePodFailed CoverageStage = "pod_failed"
)

// terminalTargetRetention bounds how long a target record survives in the
// tracker after reaching a terminal stage. Without this the tracker grows
// without bound across pod churn (deploys, HPA scale-down, evictions) since
// nothing else ever removes an entry. Kept short: the record only needs to
// outlive one heartbeat interval so the terminal event and its snapshot
// co-occur in stored telemetry at least once.
const terminalTargetRetention = 15 * time.Minute

type CoverageTransition struct {
	Stage      CoverageStage `json:"stage"`
	Reason     string        `json:"reason,omitempty"`
	ObservedAt time.Time     `json:"observed_at"`
}

// TargetActivity holds capture-liveness state for a single target.
//
// The capture path writes to it for every HTTP message, so the packet fields
// are plain atomics: no mutex, no map lookup, and no contention with other
// targets. The DaemonSet hands one of these to the target's apidump process and
// registers the same pointer with the CoverageTracker, which reads it when
// building a snapshot.
//
// Uploads are batched every few seconds, so those fields are cheap enough to
// guard with the tracker's own mutex and are not stored here.
type TargetActivity struct {
	lastPcapMessageAtNanos atomic.Int64
	lastEBPFMessageAtNanos atomic.Int64
}

// RecordPcapMessage notes an HTTP message observed by the pcap pipeline.
func (a *TargetActivity) RecordPcapMessage(at time.Time) {
	if a != nil {
		a.lastPcapMessageAtNanos.Store(at.UnixNano())
	}
}

// RecordEBPFMessage notes an HTTP message observed by the eBPF/HTTPS pipeline.
func (a *TargetActivity) RecordEBPFMessage(at time.Time) {
	if a != nil {
		a.lastEBPFMessageAtNanos.Store(at.UnixNano())
	}
}

func (a *TargetActivity) lastPcapMessageAt() *time.Time {
	return nanosToTime(a.lastPcapMessageAtNanos.Load())
}

func (a *TargetActivity) lastEBPFMessageAt() *time.Time {
	return nanosToTime(a.lastEBPFMessageAtNanos.Load())
}

func nanosToTime(nanos int64) *time.Time {
	if nanos <= 0 {
		return nil
	}
	t := time.Unix(0, nanos).UTC()
	return &t
}

type CoverageTarget struct {
	PodUID    string `json:"pod_uid"`
	PodName   string `json:"pod_name"`
	Namespace string `json:"namespace"`

	// Service and ServiceID are backend-confirmed values, set only by
	// SetResolvedService once apidump.LookupService actually resolves a
	// service (D4). ServiceNameHint is the discovery filter's guess at a
	// service name, made before any backend call -- kept separate (R5) so a
	// consumer can never mistake a hint for a confirmed identity.
	Service         string `json:"service,omitempty"`
	ServiceNameHint string `json:"service_name_hint,omitempty"`

	Workload          string               `json:"workload,omitempty"`
	ServiceID         string               `json:"service_id,omitempty"`
	WorkspaceID       string               `json:"workspace_id,omitempty"`

	// UserID and TeamID identify the Postman user/team associated with this
	// target's API key. Target-scoped, not agent-scoped: each target's
	// credentials (podArgs.PodCreds.InsightsAPIKey) can belong to a different
	// team, so this cannot be hoisted onto the shared agent_heartbeat fields.
	UserID string `json:"user_id,omitempty"`
	TeamID string `json:"team_id,omitempty"`

	CurrentStage      CoverageStage        `json:"current_stage"`
	Reason            string               `json:"reason,omitempty"`
	FailureCategory   string               `json:"failure_category,omitempty"`
	MissingAttributes []string             `json:"missing_attributes,omitempty"`
	ValidationErrors  []string             `json:"validation_errors,omitempty"`
	ObservedAt        time.Time            `json:"observed_at"`
	Transitions       []CoverageTransition `json:"transitions"`

	// Capture and delivery liveness. These are timestamps rather than counters
	// on purpose: per-service packet and upload counts already travel on the
	// service-scoped stats path, and duplicating them here would create two
	// sources of truth for the same number on two different intervals. What
	// coverage needs to answer is "is this target producing traffic, and is that
	// traffic reaching the backend" -- which a last-seen time answers directly.
	//
	// Freshness thresholds are deliberately left to the consumer, so dashboards
	// can change what counts as "currently capturing" without an agent release.
	LastPcapMessageAt *time.Time         `json:"last_pcap_message_at,omitempty"`
	LastEBPFMessageAt *time.Time         `json:"last_ebpf_message_at,omitempty"`
	LastMessageAt     *time.Time         `json:"last_message_at,omitempty"`
	LastUploadAt      *time.Time         `json:"last_upload_at,omitempty"`
	LastUploadStatus  trace.UploadStatus `json:"last_upload_status,omitempty"`

	// CaptureMode is "pcap", "ebpf", or "pcap_and_ebpf", set once capture_started
	// fires for this target. Previously only reached Amplitude via WorkflowStep,
	// not the daemonset envelope the coverage dashboard reads from.
	CaptureMode string `json:"capture_mode,omitempty"`

	// Not serialized: the live handle written by the capture path.
	activity *TargetActivity `json:"-"`
}

type CoverageSnapshot struct {
	AgentID string           `json:"agent_id"`
	RunID   string           `json:"run_id"`
	Targets []CoverageTarget `json:"targets"`

	// TruncatedTargets counts targets the tracker refused to admit because it was
	// at capacity. Deliberately not named "dropped": in the coverage envelope a
	// dropped target means one rejected by the capture funnel, and conflating the
	// two would make tracker capacity loss read as pods being filtered out.
	TruncatedTargets uint64 `json:"truncated_targets,omitempty"`

	// StageCounts is a non-cumulative gauge: how many currently-tracked targets
	// sit at each CoverageStage right now, at snapshot time. This is a distinct
	// question from the interval-delta event counters (how many transitions
	// happened this window) -- it answers "what does the funnel look like right
	// now", which a consumer would otherwise have to derive by aggregating the
	// full `targets` array client-side. Bounded by the number of CoverageStage
	// values, a closed set declared in this file.
	StageCounts map[CoverageStage]int `json:"stage_counts,omitempty"`
}

// CoverageTracker owns the DaemonSet's in-memory coverage state. It is kept
// separate from PodArgs so rejected targets remain observable.
type CoverageTracker struct {
	mu               sync.RWMutex
	agentID          string
	runID            string
	maxTargets       int
	targets          map[string]*CoverageTarget
	truncatedTargets uint64
}

const maxCoverageTransitionsPerTarget = 32

func (d *Daemonset) observeCoverage(pod corev1.Pod, stage CoverageStage, reason, service string) {
	// Only emit a lifecycle event when the target actually moved. The informer
	// replays its cache on handler registration and again on every resync, and
	// StartProcessInExistingPods has already walked the same pods, so an
	// unconditional emit counts each pod several times. Since `discovered` is the
	// denominator of the whole funnel, that silently corrupts every conversion
	// rate downstream.
	changed := true
	if d.Coverage != nil {
		changed = d.Coverage.Observe(pod, stage, reason, service)
	}
	if !changed {
		return
	}
	if event := coverageEventName(stage); event != "" {
		d.recordTelemetryEvent(string(pod.UID), event)
	}
}

func coverageEventName(stage CoverageStage) string {
	// D4: this used to special-case CoverageDiscoveryFilterPassed with a
	// non-empty service into "service_resolved" -- firing that event off the
	// discovery filter's guessed name, before any backend call. service_resolved
	// now only ever comes from apidump.LookupService via SetResolvedService, so
	// CoverageDiscoveryFilterPassed always maps to its own name below,
	// regardless of whether a service name hint is present.
	switch stage {
	case CoveragePodDiscovered:
		return "pod_discovered"
	case CoverageDiscoveryFilterPassed:
		return "discovery_filter_passed"
	case CoverageDiscoveryFilterRejected:
		return "discovery_filter_rejected"
	case CoveragePodConfigured:
		return "pod_configured"
	case CoveragePodConfigurationFailed:
		return "pod_configuration_failed"
	case CoveragePodStopped:
		return "pod_stopped"
	case CoveragePodFailed:
		return "pod_failed"
	default:
		return ""
	}
}

// observeCoverageByUID records a lifecycle transition for a target that is
// already known to the tracker, keyed by pod UID alone. Unlike observeCoverage
// it never creates a new target record: it exists for call sites such as the
// apidump-process goroutine that only carry a pod UID, not a full corev1.Pod,
// and that must never fabricate a coverage record for a pod the watcher has
// not itself observed.
func (d *Daemonset) observeCoverageByUID(podUID string, stage CoverageStage, reason string) {
	if d.Coverage == nil {
		return
	}
	if !d.Coverage.ObserveByUID(podUID, stage, reason) {
		return
	}
	if event := coverageEventName(stage); event != "" {
		d.recordTelemetryEvent(podUID, event)
	}
}

func (d *Daemonset) observeCoverageError(pod corev1.Pod, err error) {
	if d.Coverage == nil {
		return
	}
	var missing *allRequiredEnvVarsAbsentError
	if errors.As(err, &missing) {
		d.Coverage.SetDiagnostics(string(pod.UID), "missing_required_config", missing.missingAttrs, nil)
		return
	}
	var partial *requiredEnvVarMissingError
	if errors.As(err, &partial) {
		d.Coverage.SetDiagnostics(string(pod.UID), "missing_required_config", partial.missingAttrs, nil)
	}
}

func NewCoverageTracker(agentID, runID string, maxTargets int) *CoverageTracker {
	if maxTargets <= 0 {
		maxTargets = 1000
	}
	return &CoverageTracker{
		agentID:    agentID,
		runID:      runID,
		maxTargets: maxTargets,
		targets:    make(map[string]*CoverageTarget),
	}
}

// Observe records a target at a lifecycle stage. It reports whether this was a
// new observation: false means the target was already at this stage with this
// reason, so the caller should not emit another lifecycle event or append
// another transition.
func (t *CoverageTracker) Observe(pod corev1.Pod, stage CoverageStage, reason, service string) bool {
	if t == nil || pod.UID == "" {
		return false
	}
	now := time.Now().UTC()
	t.mu.Lock()
	defer t.mu.Unlock()

	target, exists := t.targets[string(pod.UID)]
	if !exists {
		if len(t.targets) >= t.maxTargets {
			t.truncatedTargets++
			// Warn once. Silently capping coverage makes the snapshot read as
			// "these are all the targets" when it is not, and the count alone is
			// only visible to whoever reads the payload.
			if t.truncatedTargets == 1 {
				printer.Warningf(
					"Coverage tracker reached its %d-target cap; further targets will be "+
						"absent from telemetry. See truncated_targets in the heartbeat.\n",
					t.maxTargets,
				)
			}
			return false
		}
		target = &CoverageTarget{
			PodUID:    string(pod.UID),
			PodName:   pod.Name,
			Namespace: pod.Namespace,
			Workload:  deriveWorkloadName(pod),
		}
		t.targets[target.PodUID] = target
	}
	if service != "" {
		// A guess, never a confirmed identity -- see ServiceNameHint's doc
		// comment and D4/R5 in the events matrix. Real Service/ServiceID only
		// come from SetResolvedService.
		target.ServiceNameHint = service
	}

	// A repeat of the current stage and reason is a re-observation (informer
	// replay or resync), not a transition. Keep ObservedAt fresh so the record
	// still shows liveness, but do not tell the caller anything moved.
	if exists && target.CurrentStage == stage && target.Reason == reason {
		target.ObservedAt = now
		return false
	}

	target.CurrentStage = stage
	target.Reason = reason
	target.ObservedAt = now
	if len(target.Transitions) < maxCoverageTransitionsPerTarget {
		target.Transitions = append(target.Transitions, CoverageTransition{
			Stage: stage, Reason: reason, ObservedAt: now,
		})
	}
	return true
}

// ObserveByUID records a lifecycle transition for a target already present in
// the tracker, without the full corev1.Pod that Observe requires to create a
// new record. Returns false (no event, no transition) if the target is
// unknown or the stage/reason are unchanged, same contract as Observe.
func (t *CoverageTracker) ObserveByUID(podUID string, stage CoverageStage, reason string) bool {
	if t == nil || podUID == "" {
		return false
	}
	now := time.Now().UTC()
	t.mu.Lock()
	defer t.mu.Unlock()

	target, exists := t.targets[podUID]
	if !exists {
		return false
	}
	if target.CurrentStage == stage && target.Reason == reason {
		target.ObservedAt = now
		return false
	}
	target.CurrentStage = stage
	target.Reason = reason
	target.ObservedAt = now
	if len(target.Transitions) < maxCoverageTransitionsPerTarget {
		target.Transitions = append(target.Transitions, CoverageTransition{
			Stage: stage, Reason: reason, ObservedAt: now,
		})
	}
	return true
}

// EvictTerminal removes targets that reached a terminal stage
// (CoveragePodStopped or CoveragePodFailed) more than retention ago. Called
// once per heartbeat, before Snapshot, so a terminal target is retained for at
// least one heartbeat interval -- long enough for its terminal event and a
// snapshot row to both land in stored telemetry -- without the tracker growing
// without bound across pod churn.
func (t *CoverageTracker) EvictTerminal(retention time.Duration) {
	if t == nil {
		return
	}
	cutoff := time.Now().UTC().Add(-retention)
	t.mu.Lock()
	defer t.mu.Unlock()
	for uid, target := range t.targets {
		if target.CurrentStage != CoveragePodStopped && target.CurrentStage != CoveragePodFailed {
			continue
		}
		if target.ObservedAt.Before(cutoff) {
			delete(t.targets, uid)
		}
	}
}

// targetUploadReporter adapts the coverage tracker to trace.UploadReporter for
// a single target.
type targetUploadReporter struct {
	coverage *CoverageTracker
	podUID   string
}

func (r targetUploadReporter) RecordUpload(at time.Time, status trace.UploadStatus) {
	r.coverage.RecordUpload(r.podUID, at, status)
}

// AttachActivity registers the live capture-liveness handle for a target. It is
// a no-op if the target was never discovered.
func (t *CoverageTracker) AttachActivity(podUID string, activity *TargetActivity) {
	if t == nil || podUID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if target, ok := t.targets[podUID]; ok {
		target.activity = activity
	}
}

// RecordUpload notes the outcome of one witness-report upload batch for a
// target. Called at most once per upload-batch flush, so taking the tracker
// lock here is not on any hot path.
func (t *CoverageTracker) RecordUpload(podUID string, at time.Time, status trace.UploadStatus) {
	if t == nil || podUID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	target, ok := t.targets[podUID]
	if !ok {
		return
	}
	uploadedAt := at.UTC()
	target.LastUploadAt = &uploadedAt
	target.LastUploadStatus = status
}

// SetProjectInfo records the Postman service (Insights project) and workspace
// a target was configured against, once known. Called once per target from
// the "configured" transition, since that is the earliest point the pod's
// env vars have been parsed into these IDs.
func (t *CoverageTracker) SetProjectInfo(podUID, serviceID, workspaceID string) {
	if t == nil || podUID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	target, ok := t.targets[podUID]
	if !ok {
		return
	}
	target.ServiceID = serviceID
	target.WorkspaceID = workspaceID
}

// SetResolvedService records the backend-confirmed service ID and name for a
// target, once apidump.LookupService actually resolves them (D4), and
// transitions the target to CoverageServiceResolved so the coverage gauges
// reflect it. Unlike SetProjectInfo (set at configuration time, before any
// backend call, from whatever project/workspace ID the pod was configured
// with) this always reflects a real backend response and runs later, so it is
// expected to overwrite SetProjectInfo's value with the confirmed one.
func (t *CoverageTracker) SetResolvedService(podUID, serviceID, serviceName string) {
	if t == nil || podUID == "" {
		return
	}
	now := time.Now().UTC()
	t.mu.Lock()
	defer t.mu.Unlock()
	target, ok := t.targets[podUID]
	if !ok {
		return
	}
	target.ServiceID = serviceID
	target.Service = serviceName
	target.CurrentStage = CoverageServiceResolved
	target.Reason = "resolved"
	target.ObservedAt = now
	if len(target.Transitions) < maxCoverageTransitionsPerTarget {
		target.Transitions = append(target.Transitions, CoverageTransition{
			Stage: CoverageServiceResolved, Reason: "resolved", ObservedAt: now,
		})
	}
}

// SetTrackingUser records the Postman user/team associated with a target's API
// key. Purely descriptive -- it does not move CurrentStage, since resolving
// the tracking user is a side effect of LookupService's setup, not a funnel
// stage of its own.
func (t *CoverageTracker) SetTrackingUser(podUID, userID, teamID string) {
	if t == nil || podUID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	target, ok := t.targets[podUID]
	if !ok {
		return
	}
	target.UserID = userID
	target.TeamID = teamID
}

// SetCaptureMode records this target's capture mode ("pcap", "ebpf", or
// "pcap_and_ebpf") once capture_started fires for it.
func (t *CoverageTracker) SetCaptureMode(podUID, mode string) {
	if t == nil || podUID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	target, ok := t.targets[podUID]
	if !ok {
		return
	}
	target.CaptureMode = mode
}

func (t *CoverageTracker) SetDiagnostics(podUID, category string, missing, validation []string) {
	if t == nil || podUID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	target, ok := t.targets[podUID]
	if !ok {
		return
	}
	target.FailureCategory = category
	target.MissingAttributes = append([]string(nil), missing...)
	target.ValidationErrors = append([]string(nil), validation...)
}

func (t *CoverageTracker) Snapshot() CoverageSnapshot {
	if t == nil {
		return CoverageSnapshot{}
	}
	t.mu.RLock()
	defer t.mu.RUnlock()

	keys := make([]string, 0, len(t.targets))
	for key := range t.targets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	targets := make([]CoverageTarget, 0, len(keys))
	stageCounts := make(map[CoverageStage]int, len(keys))
	for _, key := range keys {
		target := *t.targets[key]
		target.Transitions = append([]CoverageTransition(nil), target.Transitions...)

		// Materialize the live capture timestamps into the serialized record. The
		// activity handle itself is not part of the snapshot.
		if activity := target.activity; activity != nil {
			target.LastPcapMessageAt = activity.lastPcapMessageAt()
			target.LastEBPFMessageAt = activity.lastEBPFMessageAt()
			target.LastMessageAt = laterOf(target.LastPcapMessageAt, target.LastEBPFMessageAt)
		}
		target.activity = nil

		stageCounts[target.CurrentStage]++
		targets = append(targets, target)
	}
	return CoverageSnapshot{
		AgentID:          t.agentID,
		RunID:            t.runID,
		Targets:          targets,
		TruncatedTargets: t.truncatedTargets,
		StageCounts:      stageCounts,
	}
}

func laterOf(a, b *time.Time) *time.Time {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case b.After(*a):
		return b
	default:
		return a
	}
}
