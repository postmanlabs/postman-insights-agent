package kubewebhook

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// TestServer_EndToEnd starts the webhook on an OS-assigned port (plain HTTP
// — TLS is exercised in 5c.3b kind tests), posts an AdmissionReview for a
// Tomcat pod, verifies the response contains a JSON Patch, and shuts down
// gracefully. The whole test completes in well under 1 second.
//
// This is the closest analog we have to a real K8s call without standing
// up a cluster. If this passes, the request/response wiring is correct.
func TestServer_EndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mutator, err := NewMutator()
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Addr:    "127.0.0.1:0", // OS-assigned port
		Mutator: mutator,
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// 1-second deadline for shutdown is plenty for a single-conn test.
		shutdownCtx, c := context.WithTimeout(context.Background(), 1*time.Second)
		defer c()
		if err := srv.Stop(shutdownCtx); err != nil {
			t.Logf("Stop error (non-fatal in test cleanup): %v", err)
		}
	})

	if srv.ActualAddr == "" {
		t.Fatal("ActualAddr empty after Start")
	}

	// Build a realistic AdmissionReview for a Tomcat pod
	pod := newPod(corev1.Container{Name: "app", Image: "tomcat:10"})
	podJSON, _ := json.Marshal(pod)
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Request: &admissionv1.AdmissionRequest{
			UID:      "test-uid-server-e2e",
			Resource: metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
			Object:   runtime.RawExtension{Raw: podJSON},
		},
	}
	reqBody, _ := json.Marshal(review)

	// Single POST with a tight timeout
	httpClient := &http.Client{Timeout: 2 * time.Second}
	url := "http://" + srv.ActualAddr + "/mutate"
	resp, err := httpClient.Post(url, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /mutate failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d body=%s", resp.StatusCode, string(body))
	}

	var got admissionv1.AdmissionReview
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Response == nil {
		t.Fatal("response.Response is nil")
	}
	if !got.Response.Allowed {
		t.Fatal("response.Allowed = false — webhook MUST always allow")
	}
	if got.Response.UID != "test-uid-server-e2e" {
		t.Fatalf("UID round-trip failed: got %q", got.Response.UID)
	}
	if len(got.Response.Patch) == 0 {
		t.Fatal("expected non-empty patch for Java pod")
	}
	if got.Response.PatchType == nil || *got.Response.PatchType != admissionv1.PatchTypeJSONPatch {
		t.Fatalf("PatchType = %v, want JSONPatch", got.Response.PatchType)
	}
}

// TestServer_Healthz is a 50-ms test: server up, GET /healthz, expect 200.
func TestServer_Healthz(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	mutator, _ := NewMutator()
	srv := &Server{Addr: "127.0.0.1:0", Mutator: mutator}
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = srv.Stop(c)
	})

	client := &http.Client{Timeout: 1 * time.Second}
	resp, err := client.Get("http://" + srv.ActualAddr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", resp.StatusCode)
	}
}

// TestServer_MethodNotAllowed asserts /mutate rejects non-POST.
func TestServer_MethodNotAllowed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	mutator, _ := NewMutator()
	srv := &Server{Addr: "127.0.0.1:0", Mutator: mutator}
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = srv.Stop(c)
	})

	client := &http.Client{Timeout: 1 * time.Second}
	resp, err := client.Get("http://" + srv.ActualAddr + "/mutate") // GET, not POST
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}
