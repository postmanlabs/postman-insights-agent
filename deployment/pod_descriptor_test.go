package deployment

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	coreV1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestIsSensitiveEnvVar(t *testing.T) {
	testCases := []struct {
		name     string
		envVar   string
		expected bool
	}{
		// Sensitive patterns
		{"PASSWORD", "DATABASE_PASSWORD", true},
		{"password lowercase", "db_password", true},
		{"SECRET", "AWS_SECRET_KEY", true},
		{"TOKEN", "AUTH_TOKEN", true},
		{"CREDENTIAL", "MY_CREDENTIAL", true},
		{"AUTH", "OAUTH_CLIENT_ID", true},
		{"API_KEY", "STRIPE_API_KEY", true},
		{"APIKEY", "MYAPIKEY", true},
		{"PRIVATE", "PRIVATE_KEY", true},
		{"CERT", "SSL_CERT", true},
		{"PASSPHRASE", "SSH_PASSPHRASE", true},
		{"ENCRYPTION", "ENCRYPTION_KEY", true},
		{"SIGNING", "SIGNING_SECRET", true},
		{"ACCESS_KEY", "AWS_ACCESS_KEY", true},
		{"SECRET_KEY", "AWS_SECRET_KEY", true},

		// Non-sensitive patterns
		{"PORT", "PORT", false},
		{"HOST", "DATABASE_HOST", false},
		{"NAME", "APP_NAME", false},
		{"ENV", "NODE_ENV", false},
		{"VERSION", "APP_VERSION", false},
		{"LOG_LEVEL", "LOG_LEVEL", false},
		{"DEBUG", "DEBUG_MODE", false},
		{"TIMEOUT", "CONNECTION_TIMEOUT", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isSensitiveEnvVar(tc.envVar)
			assert.Equal(t, tc.expected, result, "Expected isSensitiveEnvVar(%q) to be %v", tc.envVar, tc.expected)
		})
	}
}

func TestFilterSensitiveEnvVars(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := filterSensitiveEnvVars(nil)
		assert.Nil(t, result)
	})

	t.Run("empty input returns empty map", func(t *testing.T) {
		result := filterSensitiveEnvVars(map[string]string{})
		assert.Empty(t, result)
	})

	t.Run("filters sensitive values", func(t *testing.T) {
		input := map[string]string{
			"PORT":              "8080",
			"DATABASE_PASSWORD": "super-secret",
			"APP_NAME":          "my-app",
			"API_KEY":           "sk-12345",
			"LOG_LEVEL":         "debug",
			"AUTH_TOKEN":        "bearer-token-123",
		}

		result := filterSensitiveEnvVars(input)

		assert.Equal(t, "8080", result["PORT"])
		assert.Equal(t, RedactedValue, result["DATABASE_PASSWORD"])
		assert.Equal(t, "my-app", result["APP_NAME"])
		assert.Equal(t, RedactedValue, result["API_KEY"])
		assert.Equal(t, "debug", result["LOG_LEVEL"])
		assert.Equal(t, RedactedValue, result["AUTH_TOKEN"])
	})

	t.Run("preserves key names for sensitive vars", func(t *testing.T) {
		input := map[string]string{
			"MY_SECRET": "value",
		}

		result := filterSensitiveEnvVars(input)

		_, exists := result["MY_SECRET"]
		assert.True(t, exists, "Key should be preserved")
		assert.Equal(t, RedactedValue, result["MY_SECRET"])
	})
}

func TestGetContainerState(t *testing.T) {
	testCases := []struct {
		name     string
		status   coreV1.ContainerStatus
		expected string
	}{
		{
			name: "Running state",
			status: coreV1.ContainerStatus{
				State: coreV1.ContainerState{
					Running: &coreV1.ContainerStateRunning{},
				},
			},
			expected: "Running",
		},
		{
			name: "Waiting state",
			status: coreV1.ContainerStatus{
				State: coreV1.ContainerState{
					Waiting: &coreV1.ContainerStateWaiting{},
				},
			},
			expected: "Waiting",
		},
		{
			name: "Terminated state",
			status: coreV1.ContainerStatus{
				State: coreV1.ContainerState{
					Terminated: &coreV1.ContainerStateTerminated{},
				},
			},
			expected: "Terminated",
		},
		{
			name:     "Unknown state",
			status:   coreV1.ContainerStatus{},
			expected: "Unknown",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := getContainerState(tc.status)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExtractOwnerReference(t *testing.T) {
	t.Run("no owner references", func(t *testing.T) {
		pod := coreV1.Pod{}
		kind, name := extractOwnerReference(pod)
		assert.Empty(t, kind)
		assert.Empty(t, name)
	})

	t.Run("single owner reference", func(t *testing.T) {
		pod := coreV1.Pod{
			ObjectMeta: metaV1.ObjectMeta{
				OwnerReferences: []metaV1.OwnerReference{
					{
						Kind: "ReplicaSet",
						Name: "my-deployment-abc123",
					},
				},
			},
		}
		kind, name := extractOwnerReference(pod)
		assert.Equal(t, "ReplicaSet", kind)
		assert.Equal(t, "my-deployment-abc123", name)
	})

	t.Run("prefers controller owner", func(t *testing.T) {
		controller := true
		pod := coreV1.Pod{
			ObjectMeta: metaV1.ObjectMeta{
				OwnerReferences: []metaV1.OwnerReference{
					{
						Kind: "ConfigMap",
						Name: "not-a-controller",
					},
					{
						Kind:       "ReplicaSet",
						Name:       "controller-owner",
						Controller: &controller,
					},
				},
			},
		}
		kind, name := extractOwnerReference(pod)
		assert.Equal(t, "ReplicaSet", kind)
		assert.Equal(t, "controller-owner", name)
	})
}

func TestExtractResourceSpec(t *testing.T) {
	t.Run("empty resources", func(t *testing.T) {
		result := extractResourceSpec(coreV1.ResourceList{})
		assert.Nil(t, result)
	})

	t.Run("CPU only", func(t *testing.T) {
		resources := coreV1.ResourceList{
			coreV1.ResourceCPU: resource.MustParse("500m"),
		}
		result := extractResourceSpec(resources)
		require.NotNil(t, result)
		assert.Equal(t, "500m", result.CPU)
		assert.Empty(t, result.Memory)
	})

	t.Run("memory only", func(t *testing.T) {
		resources := coreV1.ResourceList{
			coreV1.ResourceMemory: resource.MustParse("256Mi"),
		}
		result := extractResourceSpec(resources)
		require.NotNil(t, result)
		assert.Empty(t, result.CPU)
		assert.Equal(t, "256Mi", result.Memory)
	})

	t.Run("CPU and memory", func(t *testing.T) {
		resources := coreV1.ResourceList{
			coreV1.ResourceCPU:    resource.MustParse("1"),
			coreV1.ResourceMemory: resource.MustParse("1Gi"),
		}
		result := extractResourceSpec(resources)
		require.NotNil(t, result)
		assert.Equal(t, "1", result.CPU)
		assert.Equal(t, "1Gi", result.Memory)
	})
}

func TestExtractPodDescriptor(t *testing.T) {
	controller := true
	creationTime := time.Now().Add(-1 * time.Hour)

	pod := coreV1.Pod{
		ObjectMeta: metaV1.ObjectMeta{
			Name:              "my-app-pod-abc123",
			Namespace:         "production",
			UID:               types.UID("pod-uid-12345"),
			CreationTimestamp: metaV1.Time{Time: creationTime},
			Labels: map[string]string{
				"app":     "my-app",
				"version": "v1.2.3",
			},
			Annotations: map[string]string{
				"prometheus.io/scrape": "true",
			},
			OwnerReferences: []metaV1.OwnerReference{
				{
					Kind:       "ReplicaSet",
					Name:       "my-app-deployment-abc123",
					Controller: &controller,
				},
			},
		},
		Spec: coreV1.PodSpec{
			NodeName: "node-1.cluster.local",
			Containers: []coreV1.Container{
				{
					Name:  "app",
					Image: "my-app:v1.2.3",
					Resources: coreV1.ResourceRequirements{
						Requests: coreV1.ResourceList{
							coreV1.ResourceCPU:    resource.MustParse("100m"),
							coreV1.ResourceMemory: resource.MustParse("128Mi"),
						},
						Limits: coreV1.ResourceList{
							coreV1.ResourceCPU:    resource.MustParse("500m"),
							coreV1.ResourceMemory: resource.MustParse("512Mi"),
						},
					},
				},
				{
					Name:  "sidecar",
					Image: "sidecar:v1.0.0",
					Resources: coreV1.ResourceRequirements{
						Requests: coreV1.ResourceList{
							coreV1.ResourceCPU:    resource.MustParse("50m"),
							coreV1.ResourceMemory: resource.MustParse("64Mi"),
						},
						Limits: coreV1.ResourceList{
							coreV1.ResourceCPU:    resource.MustParse("100m"),
							coreV1.ResourceMemory: resource.MustParse("128Mi"),
						},
					},
				},
			},
		},
		Status: coreV1.PodStatus{
			Phase:  coreV1.PodRunning,
			PodIP:  "10.0.0.5",
			HostIP: "192.168.1.10",
			ContainerStatuses: []coreV1.ContainerStatus{
				{
					Name:         "app",
					ContainerID:  "docker://abc123",
					RestartCount: 2,
					State: coreV1.ContainerState{
						Running: &coreV1.ContainerStateRunning{},
					},
				},
				{
					Name:         "sidecar",
					ContainerID:  "docker://def456",
					RestartCount: 0,
					State: coreV1.ContainerState{
						Running: &coreV1.ContainerStateRunning{},
					},
				},
			},
		},
	}

	envVars := map[string]string{
		"PORT":              "8080",
		"DATABASE_PASSWORD": "secret123",
		"APP_NAME":          "my-app",
	}

	t.Run("extracts all pod information", func(t *testing.T) {
		result := ExtractPodDescriptor(pod, envVars)

		// Core identity
		assert.Equal(t, "pod-uid-12345", result.PodUID)
		assert.Equal(t, "my-app-pod-abc123", result.PodName)
		assert.Equal(t, "production", result.Namespace)
		assert.Equal(t, "node-1.cluster.local", result.NodeName)

		// Network
		assert.Equal(t, "10.0.0.5", result.PodIP)
		assert.Equal(t, "192.168.1.10", result.HostIP)

		// State
		assert.Equal(t, "Running", result.Phase)

		// Containers
		assert.Len(t, result.Containers, 2)
		assert.Equal(t, "app", result.Containers[0].Name)
		assert.Equal(t, "my-app:v1.2.3", result.Containers[0].Image)
		assert.Equal(t, int32(2), result.Containers[0].RestartCount)
		assert.Equal(t, "Running", result.Containers[0].State)

		// Resources (aggregated)
		require.NotNil(t, result.ResourceRequests)
		assert.Equal(t, "150m", result.ResourceRequests.CPU)
		assert.Equal(t, "192Mi", result.ResourceRequests.Memory)

		require.NotNil(t, result.ResourceLimits)
		assert.Equal(t, "600m", result.ResourceLimits.CPU)
		assert.Equal(t, "640Mi", result.ResourceLimits.Memory)

		// Labels and annotations
		assert.Equal(t, "my-app", result.Labels["app"])
		assert.Equal(t, "true", result.Annotations["prometheus.io/scrape"])

		// Owner
		assert.Equal(t, "ReplicaSet", result.OwnerKind)
		assert.Equal(t, "my-app-deployment-abc123", result.OwnerName)

		// Env vars (filtered)
		assert.Equal(t, "8080", result.EnvVars["PORT"])
		assert.Equal(t, RedactedValue, result.EnvVars["DATABASE_PASSWORD"])
		assert.Equal(t, "my-app", result.EnvVars["APP_NAME"])

		// Timestamps
		assert.Equal(t, creationTime.Unix(), result.PodCreatedAt.Unix())
		assert.False(t, result.ObservedAt.IsZero())
	})

	t.Run("handles nil env vars", func(t *testing.T) {
		result := ExtractPodDescriptor(pod, nil)
		assert.Nil(t, result.EnvVars)
	})

	t.Run("handles empty env vars", func(t *testing.T) {
		result := ExtractPodDescriptor(pod, map[string]string{})
		assert.Empty(t, result.EnvVars)
	})
}

func TestExtractContainerDescriptors(t *testing.T) {
	pod := coreV1.Pod{
		Spec: coreV1.PodSpec{
			Containers: []coreV1.Container{
				{Name: "app", Image: "my-app:v1"},
				{Name: "sidecar", Image: "sidecar:v2"},
			},
		},
		Status: coreV1.PodStatus{
			ContainerStatuses: []coreV1.ContainerStatus{
				{
					Name:         "app",
					ContainerID:  "containerd://abc",
					RestartCount: 3,
					State:        coreV1.ContainerState{Running: &coreV1.ContainerStateRunning{}},
				},
				{
					Name:         "sidecar",
					ContainerID:  "containerd://def",
					RestartCount: 0,
					State:        coreV1.ContainerState{Waiting: &coreV1.ContainerStateWaiting{}},
				},
			},
		},
	}

	result := extractContainerDescriptors(pod)

	require.Len(t, result, 2)

	assert.Equal(t, "app", result[0].Name)
	assert.Equal(t, "my-app:v1", result[0].Image)
	assert.Equal(t, "containerd://abc", result[0].ContainerID)
	assert.Equal(t, int32(3), result[0].RestartCount)
	assert.Equal(t, "Running", result[0].State)

	assert.Equal(t, "sidecar", result[1].Name)
	assert.Equal(t, "sidecar:v2", result[1].Image)
	assert.Equal(t, "containerd://def", result[1].ContainerID)
	assert.Equal(t, int32(0), result[1].RestartCount)
	assert.Equal(t, "Waiting", result[1].State)
}

func TestExtractAggregatedResources(t *testing.T) {
	pod := coreV1.Pod{
		Spec: coreV1.PodSpec{
			Containers: []coreV1.Container{
				{
					Name: "app",
					Resources: coreV1.ResourceRequirements{
						Requests: coreV1.ResourceList{
							coreV1.ResourceCPU:    resource.MustParse("100m"),
							coreV1.ResourceMemory: resource.MustParse("128Mi"),
						},
					},
				},
				{
					Name: "sidecar",
					Resources: coreV1.ResourceRequirements{
						Requests: coreV1.ResourceList{
							coreV1.ResourceCPU:    resource.MustParse("200m"),
							coreV1.ResourceMemory: resource.MustParse("256Mi"),
						},
					},
				},
			},
		},
	}

	result := extractAggregatedResources(pod, func(c coreV1.Container) coreV1.ResourceList {
		return c.Resources.Requests
	})

	require.NotNil(t, result)
	assert.Equal(t, "300m", result.CPU)
	assert.Equal(t, "384Mi", result.Memory)
}
