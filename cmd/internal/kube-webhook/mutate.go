// SPDX-License-Identifier: Apache-2.0

package kubewebhook

import (
	"encoding/json"
	"fmt"
	"regexp"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Mutator holds the configuration that the HTTP handler consults for every
// AdmissionReview request. It is constructed once at startup and used
// concurrently — no mutable state.
type Mutator struct {
	// Image regex used to detect Java containers. nil disables image-based
	// detection (env/command heuristics still apply).
	JavaImageRegex *regexp.Regexp

	// Mutation configuration passed to BuildPatch.
	PatchConfig MutationConfig
}

// NewMutator returns a Mutator with the default config (image regex from
// DefaultJavaImagePattern, default patch config).
func NewMutator() (*Mutator, error) {
	re, err := regexp.Compile(DefaultJavaImagePattern)
	if err != nil {
		return nil, fmt.Errorf("compile default image regex: %w", err)
	}
	return &Mutator{
		JavaImageRegex: re,
		PatchConfig:    DefaultMutationConfig(),
	}, nil
}

// Handle is the core decision function: takes an AdmissionRequest, returns
// an AdmissionResponse. Stateless and side-effect-free — easy to test.
//
// Decision tree:
//
//   1. Object kind isn't Pod → allow, no patch (defensive — namespace
//      selector should filter, but we double-check).
//   2. Pod can't be decoded → allow, no patch + log (don't break pod
//      creation due to a webhook bug; failurePolicy=Ignore is the safety
//      net but we also fail open in our own logic).
//   3. Pod has no Java containers → allow, no patch.
//   4. Otherwise → allow + patch.
//
// Crucially: we NEVER return Allowed=false. The webhook's job is to
// mutate, never to gate. Even on every error we admit the pod.
func (m *Mutator) Handle(req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	resp := &admissionv1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true, // we ALWAYS allow; we never gate
	}

	// (1) Kind check — defensive
	podGVR := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	if req.Resource != metav1.GroupVersionResource(podGVR) {
		return resp
	}

	// (2) Decode the pod
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		// Fail open: admit without patch + record a reason for diagnostics
		resp.Result = &metav1.Status{
			Message: fmt.Sprintf("postman-insights webhook: decode failed: %v", err),
		}
		return resp
	}

	// (3) Java detection
	javaIdx := IsJavaPod(&pod, m.JavaImageRegex)
	if len(javaIdx) == 0 {
		return resp
	}

	// (4) Build patch
	patchBytes, err := BuildPatch(&pod, javaIdx, m.PatchConfig)
	if err != nil {
		// Patch failed — fail open
		resp.Result = &metav1.Status{
			Message: fmt.Sprintf("postman-insights webhook: BuildPatch failed: %v", err),
		}
		return resp
	}

	pt := admissionv1.PatchTypeJSONPatch
	resp.Patch = patchBytes
	resp.PatchType = &pt
	return resp
}

// Scheme + codec for decoding AdmissionReview wire bytes. We don't need
// the full client-go machinery; admission/v1 register-only is enough.
var (
	scheme = runtime.NewScheme()
)

func init() {
	_ = admissionv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
}
