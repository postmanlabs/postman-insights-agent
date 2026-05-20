// SPDX-License-Identifier: Apache-2.0

package kubewebhook

import (
	"encoding/json"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func TestMutator_Handle(t *testing.T) {
	m, err := NewMutator()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name          string
		req           *admissionv1.AdmissionRequest
		wantAllowed   bool
		wantHasPatch  bool
	}{
		{
			name: "non-Pod resource → allow, no patch",
			req: &admissionv1.AdmissionRequest{
				UID:      "test-uid-1",
				Resource: metav1.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
				Object:   runtime.RawExtension{Raw: []byte(`{}`)},
			},
			wantAllowed:  true,
			wantHasPatch: false,
		},
		{
			name: "garbage pod JSON → allow + status message (fail-open)",
			req: &admissionv1.AdmissionRequest{
				UID:      "test-uid-2",
				Resource: metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
				Object:   runtime.RawExtension{Raw: []byte(`{"this is not a pod"}`)},
			},
			wantAllowed:  true,
			wantHasPatch: false,
		},
		{
			name: "non-Java pod (nginx) → allow, no patch",
			req: &admissionv1.AdmissionRequest{
				UID:      "test-uid-3",
				Resource: metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
				Object:   runtime.RawExtension{Raw: marshalPod(t, newPod(corev1.Container{Name: "nginx", Image: "nginx:1.27"}))},
			},
			wantAllowed:  true,
			wantHasPatch: false,
		},
		{
			name: "Java pod (tomcat) → allow + patch",
			req: &admissionv1.AdmissionRequest{
				UID:      "test-uid-4",
				Resource: metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
				Object:   runtime.RawExtension{Raw: marshalPod(t, newPod(corev1.Container{Name: "app", Image: "tomcat:10"}))},
			},
			wantAllowed:  true,
			wantHasPatch: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := m.Handle(tc.req)
			if resp == nil {
				t.Fatal("nil response")
			}
			if resp.Allowed != tc.wantAllowed {
				t.Fatalf("Allowed = %v, want %v", resp.Allowed, tc.wantAllowed)
			}
			if (len(resp.Patch) > 0) != tc.wantHasPatch {
				t.Fatalf("patch presence = %v (len=%d), want %v", len(resp.Patch) > 0, len(resp.Patch), tc.wantHasPatch)
			}
			if tc.wantHasPatch && resp.PatchType == nil {
				t.Fatal("patch present but PatchType is nil")
			}
			if tc.wantHasPatch && *resp.PatchType != admissionv1.PatchTypeJSONPatch {
				t.Fatalf("PatchType = %v, want JSONPatch", *resp.PatchType)
			}
			// UID must round-trip
			if resp.UID != tc.req.UID {
				t.Fatalf("UID = %q, want %q", resp.UID, tc.req.UID)
			}
		})
	}
}

// TestMutator_Handle_NeverGates is a property-style test: across many
// shapes of input, the response MUST always have Allowed=true. Gating a
// pod is never the webhook's job.
func TestMutator_Handle_NeverGates(t *testing.T) {
	m, _ := NewMutator()
	for _, raw := range [][]byte{
		nil,
		{},
		[]byte(`null`),
		[]byte(`{}`),
		[]byte(`{"corrupt":true`),
		[]byte(`malformed`),
	} {
		req := &admissionv1.AdmissionRequest{
			UID:      types.UID("never-gates"),
			Resource: metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
			Object:   runtime.RawExtension{Raw: raw},
		}
		resp := m.Handle(req)
		if !resp.Allowed {
			t.Fatalf("webhook gated on raw=%q — MUST never happen", string(raw))
		}
	}
}

func marshalPod(t *testing.T, p *corev1.Pod) []byte {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
