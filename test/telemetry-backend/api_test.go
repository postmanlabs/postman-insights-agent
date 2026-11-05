package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func getJSON(t *testing.T, s *store, path string, out any) {
	t.Helper()
	response := httptest.NewRecorder()
	newRouter(s).ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200: %s", path, response.Code, response.Body.String())
	}
	if err := json.Unmarshal(response.Body.Bytes(), out); err != nil {
		t.Fatalf("GET %s: invalid JSON: %v", path, err)
	}
}

func TestApiAgentsReturnsLatestHeartbeatPerAgent(t *testing.T) {
	s := testStore(t)
	postTelemetry(t, s, `{"agent_id":"agent-1","sequence":1,"event":"agent_heartbeat","type":"snapshot","kubernetes_cluster":"local","agent_state":"healthy","targets":[{"pod_uid":"pod-a","current_stage":"capturing"}]}`)
	postTelemetry(t, s, `{"agent_id":"agent-1","sequence":2,"event":"agent_heartbeat","type":"snapshot","kubernetes_cluster":"local","agent_state":"degraded","targets":[{"pod_uid":"pod-a","current_stage":"capturing"},{"pod_uid":"pod-b","current_stage":"pod_failed"}]}`)

	var agents []agentSummary
	getJSON(t, s, "/api/agents", &agents)
	if len(agents) != 1 {
		t.Fatalf("agents = %+v, want exactly one agent", agents)
	}
	if agents[0].AgentState != "degraded" || agents[0].TargetCount != 2 {
		t.Fatalf("agents[0] = %+v, want latest heartbeat (degraded, 2 targets)", agents[0])
	}
}

func TestApiTargetsFlattensAcrossAgents(t *testing.T) {
	s := testStore(t)
	postTelemetry(t, s, `{"agent_id":"agent-1","sequence":1,"event":"agent_heartbeat","type":"snapshot","kubernetes_cluster":"local","targets":[{"pod_uid":"pod-a","current_stage":"capturing"}]}`)
	postTelemetry(t, s, `{"agent_id":"agent-2","sequence":1,"event":"agent_heartbeat","type":"snapshot","kubernetes_cluster":"local","targets":[{"pod_uid":"pod-b","current_stage":"pod_configuration_failed"}]}`)

	var targets []targetSummary
	getJSON(t, s, "/api/targets", &targets)
	if len(targets) != 2 {
		t.Fatalf("targets = %+v, want 2 targets across both agents", targets)
	}
}

func TestApiDropReasonsSumsCounterEvents(t *testing.T) {
	s := testStore(t)
	postTelemetry(t, s, `{"agent_id":"agent-1","sequence":1,"event":"witness_pair_expired_response","type":"events","target_id":"pod-a","count":3}`)
	postTelemetry(t, s, `{"agent_id":"agent-1","sequence":2,"event":"witness_pair_expired_response","type":"events","target_id":"pod-b","count":2}`)
	postTelemetry(t, s, `{"agent_id":"agent-1","sequence":3,"event":"http_parse_failed_request_malformed","type":"events","target_id":"pod-a","count":1}`)

	var reasons []dropReasonCount
	getJSON(t, s, "/api/drop-reasons", &reasons)

	counts := map[string]int64{}
	for _, r := range reasons {
		counts[r.Event] = r.Count
	}
	if counts["witness_pair_expired_response"] != 5 {
		t.Fatalf("counts = %+v, want witness_pair_expired_response = 5", counts)
	}
	if counts["http_parse_failed_request_malformed"] != 1 {
		t.Fatalf("counts = %+v, want http_parse_failed_request_malformed = 1", counts)
	}
}

// TestApiSummaryDerivesStageCountsWithoutGaugeField guards against a real
// bug found via the live dashboard: an agent binary built before the
// stage_counts gauge field landed sends a heartbeat with a full targets
// array but no stage_counts key at all. The funnel must still populate from
// each target's own current_stage rather than reading an empty/absent gauge.
func TestApiSummaryDerivesStageCountsWithoutGaugeField(t *testing.T) {
	s := testStore(t)
	postTelemetry(t, s, `{"agent_id":"agent-1","sequence":1,"event":"agent_heartbeat","type":"snapshot","kubernetes_cluster":"local","agent_state":"healthy","targets":[{"pod_uid":"pod-a","current_stage":"pod_configured"},{"pod_uid":"pod-b","current_stage":"pod_configured"},{"pod_uid":"pod-c","current_stage":"pod_discovered"}]}`)

	var summary fleetSummary
	getJSON(t, s, "/api/summary", &summary)

	if summary.Targets.Total != 3 {
		t.Fatalf("targets.total = %d, want 3", summary.Targets.Total)
	}
	if summary.Targets.ByStage["pod_configured"] != 2 || summary.Targets.ByStage["pod_discovered"] != 1 {
		t.Fatalf("by_stage = %+v, want pod_configured=2, pod_discovered=1", summary.Targets.ByStage)
	}
}

func TestApiSummaryAggregatesFleetState(t *testing.T) {
	s := testStore(t)
	postTelemetry(t, s, `{"agent_id":"agent-1","sequence":1,"event":"agent_heartbeat","type":"snapshot","kubernetes_cluster":"local","agent_state":"healthy","targets":[{"pod_uid":"pod-a","current_stage":"capturing"},{"pod_uid":"pod-b","current_stage":"capturing"}]}`)
	postTelemetry(t, s, `{"agent_id":"agent-1","sequence":2,"event":"agent_failed","type":"events","failure_category":"kubernetes_client_init_failed"}`)
	postTelemetry(t, s, `{"agent_id":"agent-1","sequence":3,"event":"pod_failed","type":"events","target_id":"pod-c","count":2}`)

	var summary fleetSummary
	getJSON(t, s, "/api/summary", &summary)

	if summary.Agents.Total != 1 || summary.Agents.Healthy != 1 {
		t.Fatalf("agents = %+v, want 1 total, 1 healthy", summary.Agents)
	}
	if summary.Targets.Total != 2 || summary.Targets.ByStage["capturing"] != 2 {
		t.Fatalf("targets = %+v, want 2 total, stage capturing = 2", summary.Targets)
	}
	if summary.Failures.AgentFailed != 1 || summary.Failures.PodFailed != 2 {
		t.Fatalf("failures = %+v, want agent_failed=1, pod_failed=2", summary.Failures)
	}
}

func TestApiSummaryAggregatesApidumpStartCounters(t *testing.T) {
	s := testStore(t)
	postTelemetry(t, s, `{"agent_id":"agent-1","sequence":1,"event":"apidump_started","type":"events","target_id":"pod-a","count":1}`)
	postTelemetry(t, s, `{"agent_id":"agent-1","sequence":2,"event":"apidump_started","type":"events","target_id":"pod-b","count":1}`)
	postTelemetry(t, s, `{"agent_id":"agent-1","sequence":3,"event":"apidump_start_failed","type":"events","target_id":"pod-c","count":1}`)

	var summary fleetSummary
	getJSON(t, s, "/api/summary", &summary)

	if summary.ApidumpStart.Started != 2 || summary.ApidumpStart.Failed != 1 {
		t.Fatalf("apidump_start = %+v, want started=2, failed=1", summary.ApidumpStart)
	}
}
