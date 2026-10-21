package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testStore(t *testing.T) *store {
	t.Helper()
	s, err := openStore(t.TempDir() + "/telemetry.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func postTelemetry(t *testing.T, s *store, payload string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v2/agent/daemonset/telemetry", bytes.NewBufferString(payload))
	response := httptest.NewRecorder()
	newRouter(s).ServeHTTP(response, request)
	return response
}

func TestHandleTelemetryAcceptsLegacyHeartbeat(t *testing.T) {
	s := testStore(t)
	response := postTelemetry(t, s, `{"kubernetes_cluster":"local"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}

	response = httptest.NewRecorder()
	newRouter(s).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/inspect/telemetry", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("inspection status = %d, want 200", response.Code)
	}
	var records []telemetryRecord
	if err := json.Unmarshal(response.Body.Bytes(), &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Cluster != "local" {
		t.Fatalf("records = %+v, want one local record", records)
	}
}

func TestHandleTelemetrySequenceIsIdempotent(t *testing.T) {
	s := testStore(t)
	payload := `{"agent_id":"agent-1","run_id":"run-1","sequence":7,"schema_version":"v1","cluster":"local","targets":[{}]}`
	first := postTelemetry(t, s, payload)
	second := postTelemetry(t, s, payload)
	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("statuses = %d, %d, want 200", first.Code, second.Code)
	}
	records := make([]telemetryRecord, 0)
	response := httptest.NewRecorder()
	newRouter(s).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/inspect/telemetry?limit=10", nil))
	if err := json.Unmarshal(response.Body.Bytes(), &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].TargetCount != 1 {
		t.Fatalf("records = %+v, want one deduplicated record", records)
	}
}

func TestInspectTelemetryFiltersByEvent(t *testing.T) {
	s := testStore(t)
	postTelemetry(t, s, `{"agent_id":"agent-1","sequence":1,"event":"agent_heartbeat"}`)
	postTelemetry(t, s, `{"agent_id":"agent-1","sequence":2,"event":"apidump_start_failed","target_id":"pod-1","count":1}`)

	response := httptest.NewRecorder()
	newRouter(s).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/inspect/telemetry?event=apidump_start_failed", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	var records []telemetryRecord
	if err := json.Unmarshal(response.Body.Bytes(), &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || !bytes.Contains(records[0].Payload, []byte(`"target_id":"pod-1"`)) {
		t.Fatalf("records = %+v, want filtered failure event", records)
	}
}

// D1: a heartbeat POST carrying batched events must store each event as its
// own independent, individually queryable row -- not just the heartbeat
// itself -- so the raw log experience is unchanged by the transport
// optimization.
func TestHandleTelemetryFlattensBatchedEvents(t *testing.T) {
	s := testStore(t)
	payload := `{"agent_id":"agent-1","run_id":"run-1","sequence":5,"schema_version":"v1",` +
		`"kubernetes_cluster":"local","event":"agent_heartbeat","type":"snapshot","targets":[{}],` +
		`"events":[` +
		`{"type":"events","event":"pod_discovered","target_id":"pod-a","count":1,"counter_type":"interval_delta"},` +
		`{"type":"events","event":"pod_configured","target_id":"pod-a","count":1,"counter_type":"interval_delta"}` +
		`]}`
	response := postTelemetry(t, s, payload)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}

	var records []telemetryRecord
	getResponse := httptest.NewRecorder()
	newRouter(s).ServeHTTP(getResponse, httptest.NewRequest(http.MethodGet, "/inspect/telemetry?limit=10", nil))
	if err := json.Unmarshal(getResponse.Body.Bytes(), &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("records = %+v, want 3 rows (1 heartbeat + 2 flattened events)", records)
	}

	var podDiscovered, podConfigured *telemetryRecord
	for i := range records {
		if bytes.Contains(records[i].Payload, []byte(`"event":"pod_discovered"`)) {
			podDiscovered = &records[i]
		}
		if bytes.Contains(records[i].Payload, []byte(`"event":"pod_configured"`)) {
			podConfigured = &records[i]
		}
	}
	if podDiscovered == nil || podConfigured == nil {
		t.Fatalf("records = %+v, want both batched events flattened into their own rows", records)
	}
	// Inherited identity fields, not present on the wire per-event.
	if podDiscovered.AgentID != "agent-1" || podDiscovered.Cluster != "local" {
		t.Fatalf("podDiscovered = %+v, want inherited agent_id/cluster from the parent envelope", podDiscovered)
	}

	// Retrying the exact same POST must not duplicate the flattened events.
	postTelemetry(t, s, payload)
	getResponse = httptest.NewRecorder()
	newRouter(s).ServeHTTP(getResponse, httptest.NewRequest(http.MethodGet, "/inspect/telemetry?limit=10", nil))
	records = nil
	if err := json.Unmarshal(getResponse.Body.Bytes(), &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("records after retry = %+v, want still 3 rows (retry deduplicated)", records)
	}
}

func TestHandleTelemetryRejectsUnsupportedSchema(t *testing.T) {
	s := testStore(t)
	response := postTelemetry(t, s, `{"schema_version":"v2"}`)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
}

func TestHandleTelemetryRequiresConfiguredToken(t *testing.T) {
	t.Setenv("TELEMETRY_BACKEND_TOKEN", "secret")
	s := testStore(t)
	request := httptest.NewRequest(http.MethodPost, "/v2/agent/daemonset/telemetry", bytes.NewBufferString(`{}`))
	response := httptest.NewRecorder()
	newRouter(s).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
	request.Header.Set("postman-insights-verification-token", "secret")
	response = httptest.NewRecorder()
	newRouter(s).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated status = %d, want 200", response.Code)
	}
}

func TestTelemetryDashboardIsServed(t *testing.T) {
	response := httptest.NewRecorder()
	newRouter(testStore(t)).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ui", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if !bytes.Contains(response.Body.Bytes(), []byte("Fleet Health")) ||
		!bytes.Contains(response.Body.Bytes(), []byte("Coverage funnel")) {
		t.Fatal("dashboard HTML was not served")
	}
}
