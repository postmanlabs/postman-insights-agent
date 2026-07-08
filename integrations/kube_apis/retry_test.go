package kube_apis

import (
	"errors"
	"testing"

	coreV1 "k8s.io/api/core/v1"
	kubeErrs "k8s.io/apimachinery/pkg/api/errors"
)

var podResource = coreV1.Resource("pods")

func TestIsRetriableKubeErr(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "too many requests",
			err:      kubeErrs.NewTooManyRequests("get pods", 5),
			expected: true,
		},
		{
			name:     "timeout",
			err:      kubeErrs.NewTimeoutError("get pods", 0),
			expected: true,
		},
		{
			name:     "server timeout",
			err:      kubeErrs.NewServerTimeout(podResource, "get", 10),
			expected: true,
		},
		{
			name:     "service unavailable",
			err:      kubeErrs.NewServiceUnavailable("get pods"),
			expected: true,
		},
		{
			name:     "not found is fatal",
			err:      kubeErrs.NewNotFound(podResource, "missing"),
			expected: false,
		},
		{
			name:     "forbidden is fatal",
			err:      kubeErrs.NewForbidden(podResource, "get", errors.New("denied")),
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetriableKubeErr(tc.err); got != tc.expected {
				t.Fatalf("isRetriableKubeErr() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestBackoffOnKubeAPIErr(t *testing.T) {
	t.Run("retriable error requests retry", func(t *testing.T) {
		done, err := backoffOnKubeAPIErr(kubeErrs.NewTooManyRequests("get pods", 0), "get pods in agent node")
		if done {
			t.Fatal("expected done=false for retriable error")
		}
		if err != nil {
			t.Fatalf("expected nil error for retriable error, got %v", err)
		}
	})

	t.Run("fatal error is returned", func(t *testing.T) {
		fatalErr := kubeErrs.NewForbidden(podResource, "get", errors.New("denied"))
		done, err := backoffOnKubeAPIErr(fatalErr, "get pods in agent node")
		if done {
			t.Fatal("expected done=false for fatal error")
		}
		if !errors.Is(err, fatalErr) {
			t.Fatalf("expected fatal error to be returned, got %v", err)
		}
	})
}
