package rest

import "testing"

func TestDefaultObservabilityHost(t *testing.T) {
	tests := []struct {
		name   string
		region string
		env    string
		want   string
	}{
		{"US default empty env", RegionUS, "", "api.observability.postman.com"},
		{"US production", RegionUS, "PRODUCTION", "api.observability.postman.com"},
		{"US stage", RegionUS, "STAGE", "api.observability.postman-stage.com"},
		{"US beta", RegionUS, "BETA", "api.observability.postman-beta.com"},
		{"US dev", RegionUS, "DEV", "localhost:50443"},
		{"EU production empty", RegionEU, "", "api.observability.eu.postman.com"},
		{"EU production explicit", RegionEU, "PRODUCTION", "api.observability.eu.postman.com"},
		{"EU alpha", RegionEU, "ALPHA", "api.observability.eu.postman-alphta.com"},
		{"EU unknown env uses prod", RegionEU, "STAGE", "api.observability.eu.postman.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := defaultObservabilityHost(tt.region, tt.env)
			if got != tt.want {
				t.Errorf("defaultObservabilityHost(%q, %q) = %q, want %q", tt.region, tt.env, got, tt.want)
			}
		})
	}
}
