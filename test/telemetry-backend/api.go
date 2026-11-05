package main

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/nxtcoder17/ivy"
)

// targetRecord mirrors the fields of daemonset.CoverageTarget that are
// useful to display. Unmarshaled straight from a heartbeat's `targets`
// array, so field names must match coverage.go's json tags exactly.
type targetRecord struct {
	PodUID          string `json:"pod_uid"`
	PodName         string `json:"pod_name"`
	Namespace       string `json:"namespace"`
	Service         string `json:"service,omitempty"`
	ServiceNameHint string `json:"service_name_hint,omitempty"`
	ServiceID       string `json:"service_id,omitempty"`
	UserID          string `json:"user_id,omitempty"`
	TeamID          string `json:"team_id,omitempty"`

	CurrentStage    string `json:"current_stage"`
	Reason          string `json:"reason,omitempty"`
	FailureCategory string `json:"failure_category,omitempty"`

	LastPcapMessageAt *time.Time `json:"last_pcap_message_at,omitempty"`
	LastEBPFMessageAt *time.Time `json:"last_ebpf_message_at,omitempty"`
	LastMessageAt     *time.Time `json:"last_message_at,omitempty"`
	LastUploadAt      *time.Time `json:"last_upload_at,omitempty"`
	LastUploadStatus  string     `json:"last_upload_status,omitempty"`
	CaptureMode       string     `json:"capture_mode,omitempty"`
	ObservedAt        time.Time  `json:"observed_at"`
}

// heartbeatPayload mirrors the subset of rest.DaemonsetTelemetryRequest that
// a `type: snapshot` / `event: agent_heartbeat` row carries.
type heartbeatPayload struct {
	AgentID           string         `json:"agent_id"`
	RunID             string         `json:"run_id"`
	KubernetesCluster string         `json:"kubernetes_cluster"`
	Environment       string         `json:"environment"`
	AgentVersion      string         `json:"agent_version"`
	GitVersion        string         `json:"git_version"`
	AgentState        string         `json:"agent_state"`
	AgentStateSince   *time.Time     `json:"agent_state_since"`
	TruncatedTargets  uint64         `json:"truncated_targets"`
	Targets           []targetRecord `json:"targets"`

	// Not part of the wire payload; filled in from the stored row.
	ReceivedAt time.Time `json:"-"`
}

// latestHeartbeats returns the most recently received agent_heartbeat row
// for every distinct agent_id, decoded into heartbeatPayload. This is the
// single source of truth the /api/* aggregate endpoints below build on: a
// heartbeat is a full snapshot (every currently-tracked target, plus stage
// gauges), so the latest one per agent is always a complete, current fleet
// picture -- no need to replay/merge the interval-delta counter rows.
func (s *store) latestHeartbeats() ([]heartbeatPayload, error) {
	rows, err := s.db.Query(`
SELECT payload, received_at FROM telemetry_events
WHERE id IN (
	SELECT MAX(id) FROM telemetry_events
	WHERE json_extract(payload, '$.event') = 'agent_heartbeat'
	GROUP BY agent_id
)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var heartbeats []heartbeatPayload
	for rows.Next() {
		var payloadText, received string
		if err := rows.Scan(&payloadText, &received); err != nil {
			return nil, err
		}
		var hb heartbeatPayload
		if err := json.Unmarshal([]byte(payloadText), &hb); err != nil {
			return nil, err
		}
		hb.ReceivedAt, err = time.Parse(time.RFC3339Nano, received)
		if err != nil {
			return nil, err
		}
		heartbeats = append(heartbeats, hb)
	}
	return heartbeats, rows.Err()
}

type dropReasonCount struct {
	Event string `json:"event"`
	Count int64  `json:"count"`
}

// podFilters narrows the pod-level (per-target) dashboard views. Every field
// here maps to a column the real backend's daemonset_agent_counters table
// keys its ORDER BY on (postman_team_id/service_id/kubernetes_cluster/
// agent_id/target_id) -- filtering on the same set locally lets these
// dashboard queries actually validate that split, not just look like it.
type podFilters struct {
	TeamID    string
	ServiceID string
	Cluster   string
	AgentID   string
	TargetID  string
}

func podFiltersFromQuery(c *ivy.Context) podFilters {
	return podFilters{
		TeamID:    c.QueryParam("team_id"),
		ServiceID: c.QueryParam("service_id"),
		Cluster:   c.QueryParam("cluster"),
		AgentID:   c.QueryParam("agent_id"),
		TargetID:  c.QueryParam("target_id"),
	}
}

// sqlConditions renders the populated fields as json_extract(payload, ...)
// conditions plus their bind args, for callers building a WHERE clause over
// telemetry_events. cluster/agent_id use their dedicated columns instead of
// json_extract, matching the rest of this file's convention of reading
// those two off the row rather than the payload.
func (f podFilters) sqlConditions() ([]string, []any) {
	var conditions []string
	var args []any
	for _, cond := range []struct {
		value, expression string
	}{
		{f.TeamID, "json_extract(payload, '$.team_id') = ?"},
		{f.ServiceID, "json_extract(payload, '$.service_id') = ?"},
		{f.Cluster, "cluster = ?"},
		{f.AgentID, "agent_id = ?"},
		{f.TargetID, "json_extract(payload, '$.target_id') = ?"},
	} {
		if cond.value != "" {
			conditions = append(conditions, cond.expression)
			args = append(args, cond.value)
		}
	}
	return conditions, args
}

func (f podFilters) matchesTarget(t targetRecord, agentID, cluster string) bool {
	if f.TeamID != "" && t.TeamID != f.TeamID {
		return false
	}
	if f.ServiceID != "" && t.ServiceID != f.ServiceID {
		return false
	}
	if f.Cluster != "" && cluster != f.Cluster {
		return false
	}
	if f.AgentID != "" && agentID != f.AgentID {
		return false
	}
	if f.TargetID != "" && t.PodUID != f.TargetID {
		return false
	}
	return true
}

// dropReasonCounts sums the interval-delta counter rows for the four
// backend drop-reason attribution signals (witness_pair_expired,
// http_parse_failed, capture_gap_truncated, latency_anomaly), each of which
// is emitted as a family of bounded event-name suffixes (e.g.
// witness_pair_expired_request / _response). COALESCE(count, 1) covers rows
// that never carry a `count` field at all (there are none in this family
// today, but the aggregate stays correct if that ever changes).
func (s *store) dropReasonCounts(filters podFilters) ([]dropReasonCount, error) {
	query := `
SELECT json_extract(payload, '$.event') AS event,
       COALESCE(SUM(COALESCE(json_extract(payload, '$.count'), 1)), 0) AS total
FROM telemetry_events
WHERE json_extract(payload, '$.type') = 'events'
  AND (
    json_extract(payload, '$.event') LIKE 'witness_pair_expired%'
    OR json_extract(payload, '$.event') LIKE 'http_parse_failed%'
    OR json_extract(payload, '$.event') LIKE 'capture_gap_truncated%'
    OR json_extract(payload, '$.event') LIKE 'latency_anomaly%'
  )`
	conditions, args := filters.sqlConditions()
	if len(conditions) > 0 {
		query += " AND " + strings.Join(conditions, " AND ")
	}
	query += " GROUP BY event ORDER BY total DESC"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := []dropReasonCount{}
	for rows.Next() {
		var c dropReasonCount
		if err := rows.Scan(&c.Event, &c.Count); err != nil {
			return nil, err
		}
		counts = append(counts, c)
	}
	return counts, rows.Err()
}

// failureCounts sums agent_failed and pod_failed occurrences. agent_failed
// is a direct terminal report with no `count` field (COALESCE to 1 per
// row); pod_failed is a windowed interval-delta counter, so its `count`
// field can be >1 per row when multiple pods failed in the same window.
func (s *store) failureCounts() (agentFailed, podFailed int64, err error) {
	err = s.db.QueryRow(`
SELECT
	(SELECT COALESCE(SUM(COALESCE(json_extract(payload, '$.count'), 1)), 0)
	 FROM telemetry_events WHERE json_extract(payload, '$.event') = 'agent_failed'),
	(SELECT COALESCE(SUM(COALESCE(json_extract(payload, '$.count'), 1)), 0)
	 FROM telemetry_events WHERE json_extract(payload, '$.event') = 'pod_failed')
`).Scan(&agentFailed, &podFailed)
	return
}

// apidumpStartCounts sums the apidump_started / apidump_start_failed
// interval-delta counters from apidump.go's Run() -- the real "capture
// pipelines are up" signal (D2/D18), reported per target per heartbeat
// window. Unlike the coverage funnel's stage_counts, these are cumulative
// event totals, not a current-state gauge: a target's apidump_started count
// only ever grows, even after it moves on to service_resolved and beyond.
func (s *store) apidumpStartCounts() (started, failed int64, err error) {
	err = s.db.QueryRow(`
SELECT
	(SELECT COALESCE(SUM(COALESCE(json_extract(payload, '$.count'), 1)), 0)
	 FROM telemetry_events WHERE json_extract(payload, '$.event') = 'apidump_started'),
	(SELECT COALESCE(SUM(COALESCE(json_extract(payload, '$.count'), 1)), 0)
	 FROM telemetry_events WHERE json_extract(payload, '$.event') = 'apidump_start_failed')
`).Scan(&started, &failed)
	return
}

type agentSummary struct {
	AgentID          string     `json:"agent_id"`
	RunID            string     `json:"run_id"`
	Cluster          string     `json:"cluster"`
	Environment      string     `json:"environment"`
	AgentVersion     string     `json:"agent_version"`
	GitVersion       string     `json:"git_version"`
	AgentState       string     `json:"agent_state"`
	AgentStateSince  *time.Time `json:"agent_state_since,omitempty"`
	TargetCount      int        `json:"target_count"`
	TruncatedTargets uint64     `json:"truncated_targets"`
	LastHeartbeatAt  time.Time  `json:"last_heartbeat_at"`
}

// agentFilters narrows the agent-level dashboard views. Deliberately
// distinct from podFilters -- team_id/service_id are target-scoped and do
// not apply to an agent-scope row, matching the real backend's
// daemonset_agent_lifecycle_events table, which has no such columns at all.
type agentFilters struct {
	Cluster     string
	AgentID     string
	Environment string
}

func agentFiltersFromQuery(c *ivy.Context) agentFilters {
	return agentFilters{
		Cluster:     c.QueryParam("cluster"),
		AgentID:     c.QueryParam("agent_id"),
		Environment: c.QueryParam("environment"),
	}
}

func (f agentFilters) matches(hb heartbeatPayload) bool {
	if f.Cluster != "" && hb.KubernetesCluster != f.Cluster {
		return false
	}
	if f.AgentID != "" && hb.AgentID != f.AgentID {
		return false
	}
	if f.Environment != "" && hb.Environment != f.Environment {
		return false
	}
	return true
}

func (s *store) apiAgents(c *ivy.Context) error {
	heartbeats, err := s.latestHeartbeats()
	if err != nil {
		return c.Status(500).JSON(map[string]string{"error": err.Error()})
	}
	filters := agentFiltersFromQuery(c)
	agents := make([]agentSummary, 0, len(heartbeats))
	for _, hb := range heartbeats {
		if !filters.matches(hb) {
			continue
		}
		agents = append(agents, agentSummary{
			AgentID:          hb.AgentID,
			RunID:            hb.RunID,
			Cluster:          hb.KubernetesCluster,
			Environment:      hb.Environment,
			AgentVersion:     hb.AgentVersion,
			GitVersion:       hb.GitVersion,
			AgentState:       hb.AgentState,
			AgentStateSince:  hb.AgentStateSince,
			TargetCount:      len(hb.Targets),
			TruncatedTargets: hb.TruncatedTargets,
			LastHeartbeatAt:  hb.ReceivedAt,
		})
	}
	return c.JSON(agents)
}

type targetSummary struct {
	targetRecord
	AgentID string `json:"agent_id"`
	Cluster string `json:"cluster"`
}

func (s *store) apiTargets(c *ivy.Context) error {
	heartbeats, err := s.latestHeartbeats()
	if err != nil {
		return c.Status(500).JSON(map[string]string{"error": err.Error()})
	}
	filters := podFiltersFromQuery(c)
	targets := []targetSummary{}
	for _, hb := range heartbeats {
		for _, t := range hb.Targets {
			if !filters.matchesTarget(t, hb.AgentID, hb.KubernetesCluster) {
				continue
			}
			targets = append(targets, targetSummary{
				targetRecord: t,
				AgentID:      hb.AgentID,
				Cluster:      hb.KubernetesCluster,
			})
		}
	}
	return c.JSON(targets)
}

func (s *store) apiDropReasons(c *ivy.Context) error {
	counts, err := s.dropReasonCounts(podFiltersFromQuery(c))
	if err != nil {
		return c.Status(500).JSON(map[string]string{"error": err.Error()})
	}
	return c.JSON(counts)
}

type fleetSummary struct {
	Agents struct {
		Total    int `json:"total"`
		Healthy  int `json:"healthy"`
		Degraded int `json:"degraded"`
	} `json:"agents"`
	Targets struct {
		Total            int            `json:"total"`
		TruncatedTargets uint64         `json:"truncated_targets"`
		ByStage          map[string]int `json:"by_stage"`
	} `json:"targets"`
	DropReasons []dropReasonCount `json:"drop_reasons"`
	Failures    struct {
		AgentFailed int64 `json:"agent_failed"`
		PodFailed   int64 `json:"pod_failed"`
	} `json:"failures"`
	ApidumpStart struct {
		Started int64 `json:"started"`
		Failed  int64 `json:"failed"`
	} `json:"apidump_start"`
}

func (s *store) apiSummary(c *ivy.Context) error {
	heartbeats, err := s.latestHeartbeats()
	if err != nil {
		return c.Status(500).JSON(map[string]string{"error": err.Error()})
	}

	var summary fleetSummary
	summary.Targets.ByStage = map[string]int{}
	for _, hb := range heartbeats {
		summary.Agents.Total++
		if hb.AgentState == "degraded" {
			summary.Agents.Degraded++
		} else {
			summary.Agents.Healthy++
		}
		summary.Targets.Total += len(hb.Targets)
		summary.Targets.TruncatedTargets += hb.TruncatedTargets
		// Derived from each target's own current_stage rather than trusting
		// the heartbeat's stage_counts gauge field: that field is a newer
		// addition to the wire contract, so an agent binary built before it
		// landed sends heartbeats with a full targets array but no
		// stage_counts at all. Counting per-target is correct either way and
		// never silently produces an empty funnel against valid data.
		for _, t := range hb.Targets {
			if t.CurrentStage != "" {
				summary.Targets.ByStage[t.CurrentStage]++
			}
		}
	}

	summary.DropReasons, err = s.dropReasonCounts(podFilters{})
	if err != nil {
		return c.Status(500).JSON(map[string]string{"error": err.Error()})
	}

	summary.Failures.AgentFailed, summary.Failures.PodFailed, err = s.failureCounts()
	if err != nil {
		return c.Status(500).JSON(map[string]string{"error": err.Error()})
	}

	summary.ApidumpStart.Started, summary.ApidumpStart.Failed, err = s.apidumpStartCounts()
	if err != nil {
		return c.Status(500).JSON(map[string]string{"error": err.Error()})
	}

	return c.JSON(summary)
}
