package main

import (
	"database/sql"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nxtcoder17/ivy"
)

// ============================================================================
// Dashboard 1: Fleet health / liveness
// ============================================================================

type failureCategoryCount struct {
	Category string `json:"category"`
	Count    int64  `json:"count"`
}

// failureBreakdown groups agent_failed occurrences by failure_category.
// agent_failed is agent-scope only (never a target_id), so this filters on
// agentFilters rather than podFilters -- there is no service/team axis to
// slice a startup/runtime failure by.
func (s *store) failureBreakdown(filters agentFilters) ([]failureCategoryCount, error) {
	query := `
SELECT COALESCE(NULLIF(json_extract(payload, '$.failure_category'), ''), '(uncategorized)') AS category,
       COUNT(*) AS total
FROM telemetry_events
WHERE json_extract(payload, '$.event') = 'agent_failed'`
	conditions, args := filters.sqlConditions()
	if len(conditions) > 0 {
		query += " AND " + strings.Join(conditions, " AND ")
	}
	query += " GROUP BY category ORDER BY total DESC"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := []failureCategoryCount{}
	for rows.Next() {
		var c failureCategoryCount
		if err := rows.Scan(&c.Category, &c.Count); err != nil {
			return nil, err
		}
		counts = append(counts, c)
	}
	return counts, rows.Err()
}

// sqlConditions renders agentFilters as column-based conditions. cluster,
// agent_id, and environment are all dedicated columns on telemetry_events
// already (see openStore's schema), so no json_extract needed here.
func (f agentFilters) sqlConditions() ([]string, []any) {
	var conditions []string
	var args []any
	for _, cond := range []struct {
		value, expression string
	}{
		{f.Cluster, "cluster = ?"},
		{f.AgentID, "agent_id = ?"},
		{f.Environment, "environment = ?"},
	} {
		if cond.value != "" {
			conditions = append(conditions, cond.expression)
			args = append(args, cond.value)
		}
	}
	return conditions, args
}

type lifecycleEvent struct {
	ReceivedAt      time.Time `json:"received_at"`
	AgentID         string    `json:"agent_id"`
	Cluster         string    `json:"cluster"`
	Environment     string    `json:"environment"`
	Event           string    `json:"event"`
	AgentState      string    `json:"agent_state,omitempty"`
	FailureCategory string    `json:"failure_category,omitempty"`
}

// agentLifecycleEvents returns the most recent agent-scope rows (never a
// target_id) as a flat timeline -- agent_started/agent_heartbeat/
// agent_stopped/agent_failed/kubernetes_client_ready interleaved in arrival
// order, so a start/stop/crash sequence for one agent reads top to bottom.
func (s *store) agentLifecycleEvents(filters agentFilters, limit int) ([]lifecycleEvent, error) {
	query := `
SELECT received_at, agent_id, cluster, environment,
       json_extract(payload, '$.event') AS event,
       json_extract(payload, '$.agent_state') AS agent_state,
       json_extract(payload, '$.failure_category') AS failure_category
FROM telemetry_events
WHERE (json_extract(payload, '$.target_id') IS NULL OR json_extract(payload, '$.target_id') = '')`
	conditions, args := filters.sqlConditions()
	if len(conditions) > 0 {
		query += " AND " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := []lifecycleEvent{}
	for rows.Next() {
		var e lifecycleEvent
		var received string
		var agentState, failureCategory sql.NullString
		if err := rows.Scan(&received, &e.AgentID, &e.Cluster, &e.Environment, &e.Event, &agentState, &failureCategory); err != nil {
			return nil, err
		}
		e.ReceivedAt, err = time.Parse(time.RFC3339Nano, received)
		if err != nil {
			return nil, err
		}
		e.AgentState, e.FailureCategory = agentState.String, failureCategory.String
		events = append(events, e)
	}
	return events, rows.Err()
}

func (s *store) apiFailureBreakdown(c *ivy.Context) error {
	counts, err := s.failureBreakdown(agentFiltersFromQuery(c))
	if err != nil {
		return c.Status(500).JSON(map[string]string{"error": err.Error()})
	}
	return c.JSON(counts)
}

func (s *store) apiAgentLifecycle(c *ivy.Context) error {
	limit := queryLimit(c, 200)
	events, err := s.agentLifecycleEvents(agentFiltersFromQuery(c), limit)
	if err != nil {
		return c.Status(500).JSON(map[string]string{"error": err.Error()})
	}
	return c.JSON(events)
}

// ============================================================================
// Dashboard 2: Fleet composition / rollout
// ============================================================================

type versionCount struct {
	Version string `json:"version"`
	Count   int    `json:"count"`
}

type versionAdoptionSummary struct {
	AgentVersions []versionCount `json:"agent_versions"`
	GitVersions   []versionCount `json:"git_versions"`
}

// versionAdoption groups the latest heartbeat per agent by agent_version and
// (separately) git_version. Uses latestHeartbeats(), same as apiAgents --
// each agent counted exactly once, at its current version, not once per
// heartbeat it ever sent.
func (s *store) versionAdoption(filters agentFilters) (versionAdoptionSummary, error) {
	heartbeats, err := s.latestHeartbeats()
	if err != nil {
		return versionAdoptionSummary{}, err
	}
	agentVersions := map[string]int{}
	gitVersions := map[string]int{}
	for _, hb := range heartbeats {
		if !filters.matches(hb) {
			continue
		}
		agentVersions[orUnknown(hb.AgentVersion)]++
		gitVersions[orUnknown(hb.GitVersion)]++
	}
	return versionAdoptionSummary{
		AgentVersions: sortedVersionCounts(agentVersions),
		GitVersions:   sortedVersionCounts(gitVersions),
	}, nil
}

func orUnknown(s string) string {
	if s == "" {
		return "(unknown)"
	}
	return s
}

func sortedVersionCounts(m map[string]int) []versionCount {
	counts := make([]versionCount, 0, len(m))
	for v, n := range m {
		counts = append(counts, versionCount{Version: v, Count: n})
	}
	sort.Slice(counts, func(i, j int) bool { return counts[i].Count > counts[j].Count })
	return counts
}

type clusterInventoryRow struct {
	Cluster         string    `json:"cluster"`
	Environment     string    `json:"environment"`
	AgentCount      int       `json:"agent_count"`
	LastHeartbeatAt time.Time `json:"last_heartbeat_at"`
}

// clusterInventory lists every distinct (cluster, environment) pair
// currently reporting, with how many agents and how recently. Fleet-wide by
// design -- this answers "where is the agent even running," so it does not
// take agentFilters (filtering out a cluster here would defeat the point).
func (s *store) clusterInventory() ([]clusterInventoryRow, error) {
	heartbeats, err := s.latestHeartbeats()
	if err != nil {
		return nil, err
	}
	type key struct{ cluster, environment string }
	rowsByKey := map[key]*clusterInventoryRow{}
	for _, hb := range heartbeats {
		k := key{hb.KubernetesCluster, hb.Environment}
		row, ok := rowsByKey[k]
		if !ok {
			row = &clusterInventoryRow{Cluster: hb.KubernetesCluster, Environment: hb.Environment}
			rowsByKey[k] = row
		}
		row.AgentCount++
		if hb.ReceivedAt.After(row.LastHeartbeatAt) {
			row.LastHeartbeatAt = hb.ReceivedAt
		}
	}
	out := make([]clusterInventoryRow, 0, len(rowsByKey))
	for _, row := range rowsByKey {
		out = append(out, *row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Cluster < out[j].Cluster })
	return out, nil
}

func (s *store) apiVersionAdoption(c *ivy.Context) error {
	summary, err := s.versionAdoption(agentFiltersFromQuery(c))
	if err != nil {
		return c.Status(500).JSON(map[string]string{"error": err.Error()})
	}
	return c.JSON(summary)
}

func (s *store) apiClusterInventory(c *ivy.Context) error {
	rows, err := s.clusterInventory()
	if err != nil {
		return c.Status(500).JSON(map[string]string{"error": err.Error()})
	}
	return c.JSON(rows)
}

// ============================================================================
// Dashboard 4: Drop-reason attribution -- per-cluster breakdown
// ============================================================================

type dropReasonByCluster struct {
	Event   string `json:"event"`
	Cluster string `json:"cluster"`
	Count   int64  `json:"count"`
}

// dropReasonCountsByCluster is dropReasonCounts (see api.go) with cluster
// added to the grouping, so a noisy cluster is visible instead of averaged
// into the fleet-wide total.
func (s *store) dropReasonCountsByCluster(filters podFilters) ([]dropReasonByCluster, error) {
	query := `
SELECT json_extract(payload, '$.event') AS event,
       cluster,
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
	query += " GROUP BY event, cluster ORDER BY total DESC"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := []dropReasonByCluster{}
	for rows.Next() {
		var c dropReasonByCluster
		if err := rows.Scan(&c.Event, &c.Cluster, &c.Count); err != nil {
			return nil, err
		}
		counts = append(counts, c)
	}
	return counts, rows.Err()
}

func (s *store) apiDropReasonsByCluster(c *ivy.Context) error {
	counts, err := s.dropReasonCountsByCluster(podFiltersFromQuery(c))
	if err != nil {
		return c.Status(500).JSON(map[string]string{"error": err.Error()})
	}
	return c.JSON(counts)
}

// ============================================================================
// Dashboard 5: Interval counter integrity / meta
// ============================================================================

type sequenceGap struct {
	AgentID      string `json:"agent_id"`
	AfterSeq     int64  `json:"after_seq"`
	BeforeSeq    int64  `json:"before_seq"`
	MissingCount int64  `json:"missing_count"`
}

// sequenceGaps finds holes in each agent's own monotonic `sequence` counter
// among its agent-scope rows (agent_started/agent_heartbeat/agent_stopped/
// agent_failed -- the only rows that carry a real, non-synthesized sequence;
// see rest.DaemonsetTelemetryRequest.Sequence and telemetry.go's
// drainTelemetryEvents, which never sets Sequence on batched counter
// elements). A gap here means a POST never arrived at all -- distinct from
// windowGaps below, which catches a POST that arrived but whose counter
// window doesn't abut the previous one.
func (s *store) sequenceGaps(filters agentFilters) ([]sequenceGap, error) {
	query := `
SELECT agent_id, sequence
FROM telemetry_events
WHERE (json_extract(payload, '$.target_id') IS NULL OR json_extract(payload, '$.target_id') = '')
  AND sequence IS NOT NULL`
	conditions, args := filters.sqlConditions()
	if len(conditions) > 0 {
		query += " AND " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY agent_id, sequence"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var gaps []sequenceGap
	var prevAgent string
	var prevSeq int64
	first := true
	for rows.Next() {
		var agentID string
		var seq int64
		if err := rows.Scan(&agentID, &seq); err != nil {
			return nil, err
		}
		if !first && agentID == prevAgent && seq > prevSeq+1 {
			gaps = append(gaps, sequenceGap{
				AgentID:      agentID,
				AfterSeq:     prevSeq,
				BeforeSeq:    seq,
				MissingCount: seq - prevSeq - 1,
			})
		}
		prevAgent, prevSeq, first = agentID, seq, false
	}
	if gaps == nil {
		gaps = []sequenceGap{}
	}
	return gaps, rows.Err()
}

type windowGap struct {
	AgentID     string    `json:"agent_id"`
	Event       string    `json:"event"`
	TargetID    string    `json:"target_id"`
	AfterEnd    time.Time `json:"after_end"`
	BeforeStart time.Time `json:"before_start"`
	Gap         string    `json:"gap"`
}

type windowedCounterRow struct {
	AgentID     string
	Event       string
	TargetID    string
	WindowStart time.Time
	WindowEnd   time.Time
}

// windowGaps finds holes in the interval-delta counter stream: for each
// (agent_id, event, target_id), consecutive rows' [window_start, window_end)
// ranges should abut exactly, since drainTelemetryEvents (telemetry.go) sets
// windowStart to the previous flush's windowEnd. A gap here means a
// heartbeat POST was dropped or delayed enough that a whole counter window
// went missing -- the counter equivalent of what sequenceGaps catches for
// agent-scope rows.
func (s *store) windowGaps(filters podFilters) ([]windowGap, error) {
	query := `
SELECT agent_id,
       json_extract(payload, '$.event') AS event,
       json_extract(payload, '$.target_id') AS target_id,
       json_extract(payload, '$.window_start') AS window_start,
       json_extract(payload, '$.window_end') AS window_end
FROM telemetry_events
WHERE json_extract(payload, '$.counter_type') = 'interval_delta'
  AND json_extract(payload, '$.window_start') IS NOT NULL
  AND json_extract(payload, '$.window_end') IS NOT NULL`
	conditions, args := filters.sqlConditions()
	if len(conditions) > 0 {
		query += " AND " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY agent_id, event, target_id, window_start"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var all []windowedCounterRow
	for rows.Next() {
		var r windowedCounterRow
		var start, end string
		if err := rows.Scan(&r.AgentID, &r.Event, &r.TargetID, &start, &end); err != nil {
			return nil, err
		}
		r.WindowStart, err = time.Parse(time.RFC3339Nano, start)
		if err != nil {
			continue // malformed window on this row; skip rather than fail the whole report
		}
		r.WindowEnd, err = time.Parse(time.RFC3339Nano, end)
		if err != nil {
			continue
		}
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	gaps := []windowGap{}
	type key struct{ agentID, event, targetID string }
	var prevKey key
	var prevEnd time.Time
	first := true
	for _, r := range all {
		k := key{r.AgentID, r.Event, r.TargetID}
		if !first && k == prevKey && r.WindowStart.After(prevEnd) {
			gaps = append(gaps, windowGap{
				AgentID:     r.AgentID,
				Event:       r.Event,
				TargetID:    r.TargetID,
				AfterEnd:    prevEnd,
				BeforeStart: r.WindowStart,
				Gap:         r.WindowStart.Sub(prevEnd).String(),
			})
		}
		prevKey, prevEnd, first = k, r.WindowEnd, false
	}
	return gaps, nil
}

func (s *store) apiSequenceGaps(c *ivy.Context) error {
	gaps, err := s.sequenceGaps(agentFiltersFromQuery(c))
	if err != nil {
		return c.Status(500).JSON(map[string]string{"error": err.Error()})
	}
	return c.JSON(gaps)
}

func (s *store) apiWindowGaps(c *ivy.Context) error {
	gaps, err := s.windowGaps(podFiltersFromQuery(c))
	if err != nil {
		return c.Status(500).JSON(map[string]string{"error": err.Error()})
	}
	return c.JSON(gaps)
}

// ============================================================================
// Shared helpers
// ============================================================================

func queryLimit(c *ivy.Context, def int) int {
	limit := def
	if v := c.QueryParam("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	return limit
}
