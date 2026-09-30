package daemonset

import (
	"net/http"
	"strings"
	"testing"
)

func applyTelemetryAuth(t *testing.T, auth telemetryAuth) http.Header {
	t.Helper()
	if !auth.enabled {
		t.Fatal("telemetry auth is disabled")
	}
	req, err := http.NewRequest(http.MethodPost, "https://example.test/v2/agent/daemonset/telemetry", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.handler(req); err != nil {
		t.Fatal(err)
	}
	return req.Header
}

func TestSelectTelemetryAuth(t *testing.T) {
	t.Run("verification token", func(t *testing.T) {
		auth := selectTelemetryAuth("tvt_token", "api-key", "production")
		if !auth.enabled || auth.viaAPIKey {
			t.Fatalf("enabled=%v viaAPIKey=%v", auth.enabled, auth.viaAPIKey)
		}
		header := applyTelemetryAuth(t, auth)
		if got := header.Get("postman-insights-verification-token"); got != "tvt_token" {
			t.Fatalf("verification token header = %q", got)
		}
		if got := header.Get("x-api-key"); got != "" {
			t.Fatalf("x-api-key = %q, want empty when a verification token is set", got)
		}
	})

	t.Run("api key fallback", func(t *testing.T) {
		auth := selectTelemetryAuth("", "api-key", "production")
		if !auth.enabled || !auth.viaAPIKey {
			t.Fatalf("enabled=%v viaAPIKey=%v", auth.enabled, auth.viaAPIKey)
		}
		header := applyTelemetryAuth(t, auth)
		if got := header.Get("x-api-key"); got != "api-key" {
			t.Fatalf("x-api-key = %q", got)
		}
		if got := header.Get("x-postman-env"); got != "production" {
			t.Fatalf("x-postman-env = %q", got)
		}
		if got := header.Get("postman-insights-verification-token"); got != "" {
			t.Fatalf("verification token header = %q, want empty", got)
		}
	})

	t.Run("api key without environment", func(t *testing.T) {
		header := applyTelemetryAuth(t, selectTelemetryAuth("", "api-key", ""))
		if got := header.Get("x-api-key"); got != "api-key" {
			t.Fatalf("x-api-key = %q", got)
		}
		if got := header.Get("x-postman-env"); got != "" {
			t.Fatalf("x-postman-env = %q, want empty", got)
		}
	})

	t.Run("neither credential", func(t *testing.T) {
		auth := selectTelemetryAuth("", "", "")
		if auth.enabled || auth.handler != nil || auth.viaAPIKey {
			t.Fatalf("enabled=%v viaAPIKey=%v handler set=%v", auth.enabled, auth.viaAPIKey, auth.handler != nil)
		}
	})
}

func TestResolveTelemetryClusterName(t *testing.T) {
	t.Run("explicit name", func(t *testing.T) {
		got, err := resolveTelemetryClusterName("prod-cluster", false)
		if err != nil {
			t.Fatal(err)
		}
		if got != "prod-cluster" {
			t.Fatalf("cluster name = %q", got)
		}
	})

	t.Run("explicit name in discovery mode", func(t *testing.T) {
		got, err := resolveTelemetryClusterName("prod-cluster", true)
		if err != nil {
			t.Fatal(err)
		}
		if got != "prod-cluster" {
			t.Fatalf("cluster name = %q", got)
		}
	})

	t.Run("default outside discovery mode", func(t *testing.T) {
		got, err := resolveTelemetryClusterName("", false)
		if err != nil {
			t.Fatal(err)
		}
		if got != DefaultTelemetryClusterName {
			t.Fatalf("cluster name = %q, want %q", got, DefaultTelemetryClusterName)
		}
	})

	t.Run("discovery mode requires a name", func(t *testing.T) {
		_, err := resolveTelemetryClusterName("", true)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "POSTMAN_INSIGHTS_CLUSTER_NAME") {
			t.Fatalf("error = %q", err)
		}
	})
}
