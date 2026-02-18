package daemonset

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newTestPod(namespace, name string, labels, annotations map[string]string, ownerKind, ownerName string) corev1.Pod {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
	}
	if ownerKind != "" {
		pod.OwnerReferences = []metav1.OwnerReference{
			{Kind: ownerKind, Name: ownerName},
		}
	}
	return pod
}

func TestAgentSelfSkip(t *testing.T) {
	f := NewPodFilter("insights-agent-abc", nil, nil, nil, nil)

	agentPod := newTestPod("default", "insights-agent-abc", nil, nil, "DaemonSet", "insights-agent")
	otherPod := newTestPod("default", "api-abc", nil, nil, "ReplicaSet", "api-abc123")

	if r := f.Evaluate(agentPod); r.ShouldCapture {
		t.Errorf("expected agent's own pod to be excluded")
	}
	if r := f.Evaluate(otherPod); !r.ShouldCapture {
		t.Errorf("expected other pod to be captured, reason: %s", r.Reason)
	}
}

func TestNamespaceFilter_ExcludeDefault(t *testing.T) {
	f := NewPodFilter("", nil, nil, nil, nil)
	pod := newTestPod("kube-system", "coredns-abc", nil, nil, "ReplicaSet", "coredns-abc123")
	result := f.Evaluate(pod)
	if result.ShouldCapture {
		t.Errorf("expected kube-system pod to be excluded, got capture=true")
	}
}

func TestNamespaceFilter_ExcludeCustom(t *testing.T) {
	f := NewPodFilter("", nil, []string{"redis-ns"}, nil, nil)
	pod := newTestPod("redis-ns", "redis-0", nil, nil, "StatefulSet", "redis")
	result := f.Evaluate(pod)
	if result.ShouldCapture {
		t.Errorf("expected redis-ns to be excluded, got capture=true")
	}
}

func TestNamespaceFilter_IncludeOnly(t *testing.T) {
	f := NewPodFilter("", []string{"production"}, nil, nil, nil)

	prod := newTestPod("production", "api-abc", nil, nil, "ReplicaSet", "api-abc123")
	staging := newTestPod("staging", "api-abc", nil, nil, "ReplicaSet", "api-abc123")

	if r := f.Evaluate(prod); !r.ShouldCapture {
		t.Errorf("expected production pod to be captured")
	}
	if r := f.Evaluate(staging); r.ShouldCapture {
		t.Errorf("expected staging pod to be excluded when include=production")
	}
}

func TestAnnotationFilter_OptOut(t *testing.T) {
	f := NewPodFilter("", nil, nil, nil, nil)
	pod := newTestPod("default", "api-xyz", nil, map[string]string{
		AnnotationOptOut: "true",
	}, "ReplicaSet", "api-xyz123")
	result := f.Evaluate(pod)
	if result.ShouldCapture {
		t.Errorf("expected opt-out pod to be excluded")
	}
}

func TestLabelFilter_Include(t *testing.T) {
	f := NewPodFilter("", nil, nil, map[string]string{"app": "my-api"}, nil)

	match := newTestPod("default", "my-api-abc", map[string]string{"app": "my-api"}, nil, "ReplicaSet", "my-api-abc123")
	noMatch := newTestPod("default", "redis-abc", map[string]string{"app": "redis"}, nil, "ReplicaSet", "redis-abc123")

	if r := f.Evaluate(match); !r.ShouldCapture {
		t.Errorf("expected pod matching include label to be captured")
	}
	if r := f.Evaluate(noMatch); r.ShouldCapture {
		t.Errorf("expected pod not matching include label to be excluded")
	}
}

func TestLabelFilter_Exclude(t *testing.T) {
	f := NewPodFilter("", nil, nil, nil, map[string]string{"app": "redis"})

	redis := newTestPod("default", "redis-abc", map[string]string{"app": "redis"}, nil, "ReplicaSet", "redis-abc123")
	api := newTestPod("default", "api-abc", map[string]string{"app": "my-api"}, nil, "ReplicaSet", "api-abc123")

	if r := f.Evaluate(redis); r.ShouldCapture {
		t.Errorf("expected redis pod to be excluded by exclude label")
	}
	if r := f.Evaluate(api); !r.ShouldCapture {
		t.Errorf("expected api pod to be captured")
	}
}

func TestControllerTypeFilter_Job(t *testing.T) {
	f := NewPodFilter("", nil, nil, nil, nil)
	pod := newTestPod("default", "data-job-abc", nil, nil, "Job", "data-job")
	result := f.Evaluate(pod)
	if result.ShouldCapture {
		t.Errorf("expected Job pod to be excluded")
	}
}

func TestControllerTypeFilter_StandalonePod(t *testing.T) {
	f := NewPodFilter("", nil, nil, nil, nil)
	pod := newTestPod("default", "debug-pod", nil, nil, "", "")
	result := f.Evaluate(pod)
	if result.ShouldCapture {
		t.Errorf("expected standalone pod to be excluded")
	}
}

func TestControllerTypeFilter_Deployment(t *testing.T) {
	f := NewPodFilter("", nil, nil, nil, nil)
	pod := newTestPod("default", "user-svc-abc-def", nil, nil, "ReplicaSet", "user-svc-abc")
	result := f.Evaluate(pod)
	if !result.ShouldCapture {
		t.Errorf("expected Deployment (ReplicaSet) pod to be captured, reason: %s", result.Reason)
	}
}

func TestControllingOwner_PicksController(t *testing.T) {
	f := NewPodFilter("", nil, nil, nil, nil)
	isController := true

	// The controlling owner (ReplicaSet) appears second, but should still be chosen.
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api-abc-def",
			Namespace: "default",
		},
	}
	pod.OwnerReferences = []metav1.OwnerReference{
		{Kind: "Job", Name: "migrate-job"},
		{Kind: "ReplicaSet", Name: "api-abc", Controller: &isController},
	}

	result := f.Evaluate(pod)
	if !result.ShouldCapture {
		t.Errorf("expected pod to be captured via controlling ReplicaSet, reason: %s", result.Reason)
	}
}

func TestDeriveServiceName(t *testing.T) {
	tests := []struct {
		name     string
		pod      corev1.Pod
		expected string
	}{
		{
			name:     "ReplicaSet owned pod",
			pod:      newTestPod("default", "user-svc-abc-def", nil, nil, "ReplicaSet", "user-svc-abc123"),
			expected: "default/user-svc",
		},
		{
			name:     "StatefulSet owned pod",
			pod:      newTestPod("production", "redis-0", nil, nil, "StatefulSet", "redis"),
			expected: "production/redis",
		},
		{
			name: "Pod with app label fallback",
			pod: newTestPod("staging", "mystery-pod-xyz", map[string]string{
				"app.kubernetes.io/name": "gateway",
			}, nil, "ReplicaSet", ""),
			expected: "staging/gateway",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveServiceName(tt.pod)
			if got != tt.expected {
				t.Errorf("deriveServiceName() = %q, want %q", got, tt.expected)
			}
		})
	}
}
