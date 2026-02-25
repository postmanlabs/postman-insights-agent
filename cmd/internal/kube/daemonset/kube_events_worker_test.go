package daemonset

import (
	"testing"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	coreV1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
		name                string
		cfg                 requiredContainerConfig
		expectValidCount    int
		expectMissingCount  int
		expectValidErrCount int
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

// Helper to build a minimal pod for applyDiscoveryModeConfig tests.
func testPod(name, namespace string) coreV1.Pod {
	return coreV1.Pod{
		ObjectMeta: metaV1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{"app": "test"},
			OwnerReferences: []metaV1.OwnerReference{
				{Kind: "ReplicaSet", Name: "my-deploy-abc123"},
			},
		},
	}
}

func TestApplyDiscoveryModeConfig_NoExplicitIDs(t *testing.T) {
	d := &Daemonset{
		DiscoveryMode:       true,
		InsightsAPIKey:      "ds-api-key",
		InsightsEnvironment: "production",
		ClusterName:         "test-cluster",
	}
	pod := testPod("my-pod", "default")
	podArgs := NewPodArgs(pod.Name)

	err := d.applyDiscoveryModeConfig(pod, podArgs, containerConfig{})
	require.NoError(t, err)

	assert.True(t, podArgs.DiscoveryMode)
	assert.Equal(t, "default/my-deploy", podArgs.DiscoveryServiceName)
	assert.Equal(t, "test-cluster", podArgs.ClusterName)
	assert.Equal(t, "default", podArgs.Namespace)
	assert.Equal(t, "ds-api-key", podArgs.PodCreds.InsightsAPIKey)
	assert.Equal(t, "production", podArgs.PodCreds.InsightsEnvironment)
	assert.Equal(t, akid.ServiceID{}, podArgs.InsightsProjectID)
	assert.Empty(t, podArgs.WorkspaceID)
	assert.Empty(t, podArgs.SystemEnv)
}

func TestApplyDiscoveryModeConfig_NoExplicitIDs_WithServiceNameOverride(t *testing.T) {
	d := &Daemonset{
		DiscoveryMode:  true,
		InsightsAPIKey: "ds-api-key",
	}
	pod := testPod("my-pod", "default")
	podArgs := NewPodArgs(pod.Name)

	cfg := containerConfig{serviceName: "custom/service-name"}
	err := d.applyDiscoveryModeConfig(pod, podArgs, cfg)
	require.NoError(t, err)

	assert.True(t, podArgs.DiscoveryMode)
	assert.Equal(t, "custom/service-name", podArgs.DiscoveryServiceName)
}

func TestApplyDiscoveryModeConfig_WithWorkspaceID(t *testing.T) {
	validUUID := "12345678-1234-1234-1234-123456789abc"
	validSystemEnv := "abcdefab-abcd-abcd-abcd-abcdefabcdef"

	d := &Daemonset{
		DiscoveryMode:       true,
		InsightsAPIKey:      "ds-api-key",
		InsightsEnvironment: "production",
	}
	pod := testPod("my-pod", "default")
	podArgs := NewPodArgs(pod.Name)

	cfg := containerConfig{
		requiredContainerConfig: requiredContainerConfig{
			workspaceID: validUUID,
			systemEnv:   validSystemEnv,
			apiKey:      "pod-api-key",
		},
	}
	err := d.applyDiscoveryModeConfig(pod, podArgs, cfg)
	require.NoError(t, err)

	assert.False(t, podArgs.DiscoveryMode)
	assert.Equal(t, validUUID, podArgs.WorkspaceID)
	assert.Equal(t, validSystemEnv, podArgs.SystemEnv)
	assert.Equal(t, "pod-api-key", podArgs.PodCreds.InsightsAPIKey)
	assert.Equal(t, "production", podArgs.PodCreds.InsightsEnvironment)
	assert.Equal(t, akid.ServiceID{}, podArgs.InsightsProjectID)
}

func TestApplyDiscoveryModeConfig_WithProjectID(t *testing.T) {
	validServiceID := akid.GenerateServiceID()

	d := &Daemonset{
		DiscoveryMode:       true,
		InsightsAPIKey:      "ds-api-key",
		InsightsEnvironment: "production",
	}
	pod := testPod("my-pod", "default")
	podArgs := NewPodArgs(pod.Name)

	cfg := containerConfig{
		requiredContainerConfig: requiredContainerConfig{
			projectID: validServiceID.String(),
			apiKey:    "pod-api-key",
		},
	}
	err := d.applyDiscoveryModeConfig(pod, podArgs, cfg)
	require.NoError(t, err)

	assert.False(t, podArgs.DiscoveryMode)
	assert.Equal(t, validServiceID, podArgs.InsightsProjectID)
	assert.Empty(t, podArgs.WorkspaceID)
	assert.Equal(t, "pod-api-key", podArgs.PodCreds.InsightsAPIKey)
}

func TestApplyDiscoveryModeConfig_ExplicitIDs_FallbackToDaemonSetAPIKey(t *testing.T) {
	validUUID := "12345678-1234-1234-1234-123456789abc"

	d := &Daemonset{
		DiscoveryMode:       true,
		InsightsAPIKey:      "ds-api-key",
		InsightsEnvironment: "staging",
	}
	pod := testPod("my-pod", "default")
	podArgs := NewPodArgs(pod.Name)

	cfg := containerConfig{
		requiredContainerConfig: requiredContainerConfig{
			workspaceID: validUUID,
			systemEnv:   validUUID,
			// apiKey intentionally left empty
		},
	}
	err := d.applyDiscoveryModeConfig(pod, podArgs, cfg)
	require.NoError(t, err)

	assert.False(t, podArgs.DiscoveryMode)
	assert.Equal(t, "ds-api-key", podArgs.PodCreds.InsightsAPIKey)
	assert.Equal(t, "staging", podArgs.PodCreds.InsightsEnvironment)
}

func TestApplyDiscoveryModeConfig_InvalidWorkspaceUUID(t *testing.T) {
	d := &Daemonset{DiscoveryMode: true, InsightsAPIKey: "ds-key"}
	pod := testPod("my-pod", "default")
	podArgs := NewPodArgs(pod.Name)

	cfg := containerConfig{
		requiredContainerConfig: requiredContainerConfig{
			workspaceID: "not-a-uuid",
			systemEnv:   "12345678-1234-1234-1234-123456789abc",
		},
	}
	err := d.applyDiscoveryModeConfig(pod, podArgs, cfg)

	require.Error(t, err)
	assert.Contains(t, err.Error(), POSTMAN_INSIGHTS_WORKSPACE_ID)
	assert.Contains(t, err.Error(), "valid UUID")
}

func TestApplyDiscoveryModeConfig_MissingSystemEnv(t *testing.T) {
	d := &Daemonset{DiscoveryMode: true, InsightsAPIKey: "ds-key"}
	pod := testPod("my-pod", "default")
	podArgs := NewPodArgs(pod.Name)

	cfg := containerConfig{
		requiredContainerConfig: requiredContainerConfig{
			workspaceID: "12345678-1234-1234-1234-123456789abc",
			// systemEnv intentionally missing
		},
	}
	err := d.applyDiscoveryModeConfig(pod, podArgs, cfg)

	require.Error(t, err)
	assert.Contains(t, err.Error(), POSTMAN_INSIGHTS_SYSTEM_ENV)
	assert.Contains(t, err.Error(), "required")
}

func TestApplyDiscoveryModeConfig_InvalidSystemEnvUUID(t *testing.T) {
	d := &Daemonset{DiscoveryMode: true, InsightsAPIKey: "ds-key"}
	pod := testPod("my-pod", "default")
	podArgs := NewPodArgs(pod.Name)

	cfg := containerConfig{
		requiredContainerConfig: requiredContainerConfig{
			workspaceID: "12345678-1234-1234-1234-123456789abc",
			systemEnv:   "bad-uuid",
		},
	}
	err := d.applyDiscoveryModeConfig(pod, podArgs, cfg)

	require.Error(t, err)
	assert.Contains(t, err.Error(), POSTMAN_INSIGHTS_SYSTEM_ENV)
	assert.Contains(t, err.Error(), "valid UUID")
}

func TestApplyDiscoveryModeConfig_InvalidProjectID(t *testing.T) {
	d := &Daemonset{DiscoveryMode: true, InsightsAPIKey: "ds-key"}
	pod := testPod("my-pod", "default")
	podArgs := NewPodArgs(pod.Name)

	cfg := containerConfig{
		requiredContainerConfig: requiredContainerConfig{
			projectID: "not-a-valid-akid",
		},
	}
	err := d.applyDiscoveryModeConfig(pod, podArgs, cfg)

	require.Error(t, err)
	assert.Contains(t, err.Error(), POSTMAN_INSIGHTS_PROJECT_ID)
}

func TestApplyDiscoveryModeConfig_OptionalConfigsApplied(t *testing.T) {
	d := &Daemonset{
		DiscoveryMode:            true,
		InsightsAPIKey:           "ds-api-key",
		InsightsReproModeEnabled: true,
		InsightsRateLimit:        42.0,
	}
	pod := testPod("my-pod", "default")
	podArgs := NewPodArgs(pod.Name)

	cfg := containerConfig{
		alwaysCapturePayloads: `["/health","/ready"]`,
	}
	err := d.applyDiscoveryModeConfig(pod, podArgs, cfg)
	require.NoError(t, err)

	assert.True(t, podArgs.DiscoveryMode)
	assert.True(t, podArgs.ReproMode)
	assert.Equal(t, 42.0, podArgs.AgentRateLimit)
	assert.Equal(t, []string{"/health", "/ready"}, podArgs.AlwaysCapturePayloads)
}
