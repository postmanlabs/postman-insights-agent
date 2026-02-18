package daemonset

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateContainerConfig_TraditionalMode(t *testing.T) {
	tests := []struct {
		name               string
		cfg                requiredContainerConfig
		expectValidCount   int
		expectMissingCount int
		expectMissing      []string
	}{
		{
			name: "all fields present",
			cfg: requiredContainerConfig{
				projectID: "svc_abc123",
				apiKey:    "PMK-test-key",
			},
			expectValidCount:   2,
			expectMissingCount: 0,
		},
		{
			name: "missing api key",
			cfg: requiredContainerConfig{
				projectID: "svc_abc123",
			},
			expectValidCount:   1,
			expectMissingCount: 1,
			expectMissing:      []string{POSTMAN_INSIGHTS_API_KEY},
		},
		{
			name: "missing project ID",
			cfg: requiredContainerConfig{
				apiKey: "PMK-test-key",
			},
			expectValidCount:   1,
			expectMissingCount: 1,
			expectMissing:      []string{POSTMAN_INSIGHTS_PROJECT_ID},
		},
		{
			name:               "all fields missing",
			cfg:                requiredContainerConfig{},
			expectValidCount:   0,
			expectMissingCount: 2,
			expectMissing:      []string{POSTMAN_INSIGHTS_API_KEY, POSTMAN_INSIGHTS_PROJECT_ID},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateContainerConfig(tt.cfg)
			assert.Equal(t, tt.expectValidCount, result.ValidAttrCount)
			assert.Len(t, result.MissingAttrs, tt.expectMissingCount)
			if tt.expectMissing != nil {
				assert.Equal(t, tt.expectMissing, result.MissingAttrs)
			}
		})
	}
}

func TestValidateContainerConfig_WorkspaceMode(t *testing.T) {
	validUUID := "12345678-1234-1234-1234-123456789abc"

	tests := []struct {
		name                 string
		cfg                  requiredContainerConfig
		expectValidCount     int
		expectMissingCount   int
		expectValidErrCount  int
	}{
		{
			name: "workspace mode - all valid",
			cfg: requiredContainerConfig{
				apiKey:      "PMK-test-key",
				workspaceID: validUUID,
				systemEnv:   validUUID,
			},
			expectValidCount:    3,
			expectMissingCount:  0,
			expectValidErrCount: 0,
		},
		{
			name: "workspace mode - missing system env",
			cfg: requiredContainerConfig{
				apiKey:      "PMK-test-key",
				workspaceID: validUUID,
			},
			expectValidCount:    2,
			expectMissingCount:  1,
			expectValidErrCount: 0,
		},
		{
			name: "workspace mode - invalid workspace UUID",
			cfg: requiredContainerConfig{
				apiKey:      "PMK-test-key",
				workspaceID: "not-a-uuid",
				systemEnv:   validUUID,
			},
			expectValidCount:    2,
			expectMissingCount:  0,
			expectValidErrCount: 1,
		},
		{
			name: "workspace mode - invalid system env UUID",
			cfg: requiredContainerConfig{
				apiKey:      "PMK-test-key",
				workspaceID: validUUID,
				systemEnv:   "not-a-uuid",
			},
			expectValidCount:    2,
			expectMissingCount:  0,
			expectValidErrCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateContainerConfig(tt.cfg)
			assert.Equal(t, tt.expectValidCount, result.ValidAttrCount)
			assert.Len(t, result.MissingAttrs, tt.expectMissingCount)
			assert.Len(t, result.ValidationErrors, tt.expectValidErrCount)
		})
	}
}

func TestValidateContainerConfig_DiscoveryModeFallback(t *testing.T) {
	// In discovery mode, the daemonset validates the container config from pod
	// env vars. If no projectID or workspaceID is found but we have an API key,
	// the daemonset falls back to the DaemonSet-level API key. This test verifies
	// that validateContainerConfig correctly identifies missing projectID when
	// only apiKey is present (the caller uses this info to decide on fallback).
	cfg := requiredContainerConfig{
		apiKey: "PMK-test-key",
	}
	result := validateContainerConfig(cfg)
	assert.Equal(t, 1, result.ValidAttrCount)
	assert.Contains(t, result.MissingAttrs, POSTMAN_INSIGHTS_PROJECT_ID)
}
