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
