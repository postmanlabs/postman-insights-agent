package kubewebhook

import (
	"encoding/json"
	"strings"
	"testing"

	jsonpatch "github.com/evanphx/json-patch/v5"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBuildPatch_NoJavaContainers_ReturnsNilPatch(t *testing.T) {
	pod := newPod(corev1.Container{Name: "nginx", Image: "nginx:1.27"})
	patch, err := BuildPatch(pod, nil, DefaultMutationConfig())
	if err != nil {
		t.Fatal(err)
	}
	if patch != nil {
		t.Fatalf("expected nil patch for no-Java pod, got %s", string(patch))
	}
}

func TestBuildPatch_NilPod(t *testing.T) {
	_, err := BuildPatch(nil, []int{0}, DefaultMutationConfig())
	if err == nil {
		t.Fatal("expected error for nil pod")
	}
}

// TestBuildPatch_RoundTrip is the most important test: it builds a patch,
// applies it to the pod JSON, decodes the result back to a Pod, and asserts
// the resulting pod has the expected structure. This is end-to-end coverage
// of the actual mutation semantics — much more meaningful than asserting
// individual patch ops.
func TestBuildPatch_RoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		pod       *corev1.Pod
		javaIdx   []int
		assertOut func(t *testing.T, mutated *corev1.Pod)
	}{
		{
			name:    "single Java container, no prior volumes / init / env",
			pod:     newPod(corev1.Container{Name: "app", Image: "eclipse-temurin:17-jre"}),
			javaIdx: []int{0},
			assertOut: func(t *testing.T, p *corev1.Pod) {
				// Volume added
				if len(p.Spec.Volumes) != 1 || p.Spec.Volumes[0].Name != agentVolumeName {
					t.Fatalf("volumes wrong: %#v", p.Spec.Volumes)
				}
				if p.Spec.Volumes[0].EmptyDir == nil {
					t.Fatal("expected emptyDir volume")
				}
				// Init container added
				if len(p.Spec.InitContainers) != 1 || p.Spec.InitContainers[0].Name != initContainerName {
					t.Fatalf("init containers wrong: %#v", p.Spec.InitContainers)
				}
				// volumeMount on the app container
				app := p.Spec.Containers[0]
				if len(app.VolumeMounts) != 1 || app.VolumeMounts[0].MountPath != agentMountPath {
					t.Fatalf("volumeMounts wrong on app: %#v", app.VolumeMounts)
				}
				// JAVA_TOOL_OPTIONS env present
				_, v := findEnvVar(app.Env, javaToolOptionsName)
				if v != javaToolOptionsArg {
					t.Fatalf("JAVA_TOOL_OPTIONS = %q, want %q", v, javaToolOptionsArg)
				}
			},
		},
		{
			name: "container with existing volume + existing JAVA_TOOL_OPTIONS — patch appends, never replaces",
			pod: func() *corev1.Pod {
				p := newPod(corev1.Container{
					Name:  "app",
					Image: "tomcat:10",
					Env: []corev1.EnvVar{
						{Name: "FOO", Value: "bar"},
						{Name: javaToolOptionsName, Value: "-Xmx2g"},
					},
					VolumeMounts: []corev1.VolumeMount{
						{Name: "config", MountPath: "/etc/app"},
					},
				})
				p.Spec.Volumes = []corev1.Volume{
					{Name: "config", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
				}
				return p
			}(),
			javaIdx: []int{0},
			assertOut: func(t *testing.T, p *corev1.Pod) {
				// Both volumes present
				if len(p.Spec.Volumes) != 2 {
					t.Fatalf("expected 2 volumes (existing+agent), got %d: %#v", len(p.Spec.Volumes), p.Spec.Volumes)
				}
				gotAgent := false
				for _, v := range p.Spec.Volumes {
					if v.Name == agentVolumeName {
						gotAgent = true
					}
				}
				if !gotAgent {
					t.Fatal("agent volume missing")
				}
				// Both volumeMounts present
				app := p.Spec.Containers[0]
				if len(app.VolumeMounts) != 2 {
					t.Fatalf("expected 2 volume mounts, got %d: %#v", len(app.VolumeMounts), app.VolumeMounts)
				}
				// JAVA_TOOL_OPTIONS appended — original -Xmx2g preserved AND -javaagent added
				_, v := findEnvVar(app.Env, javaToolOptionsName)
				if !strings.Contains(v, "-Xmx2g") {
					t.Fatalf("JAVA_TOOL_OPTIONS=%q lost original -Xmx2g", v)
				}
				if !strings.Contains(v, javaToolOptionsArg) {
					t.Fatalf("JAVA_TOOL_OPTIONS=%q missing %q", v, javaToolOptionsArg)
				}
				// FOO env preserved
				if _, fv := findEnvVar(app.Env, "FOO"); fv != "bar" {
					t.Fatalf("FOO env lost: %q", fv)
				}
			},
		},
		{
			name: "two Java containers + one non-Java sidecar — only Java containers mutated",
			pod: newPod(
				corev1.Container{Name: "sidecar", Image: "nginx:1.27"},
				corev1.Container{Name: "app1",    Image: "eclipse-temurin:17-jre"},
				corev1.Container{Name: "app2",    Image: "tomcat:10"},
			),
			javaIdx: []int{1, 2},
			assertOut: func(t *testing.T, p *corev1.Pod) {
				// sidecar (index 0): unmodified
				if len(p.Spec.Containers[0].VolumeMounts) != 0 || len(p.Spec.Containers[0].Env) != 0 {
					t.Fatalf("non-Java sidecar got mutated: %#v", p.Spec.Containers[0])
				}
				// app1 (index 1) and app2 (index 2): mutated
				for _, idx := range []int{1, 2} {
					c := p.Spec.Containers[idx]
					if len(c.VolumeMounts) != 1 || c.VolumeMounts[0].MountPath != agentMountPath {
						t.Fatalf("container[%d] volumeMounts wrong: %#v", idx, c.VolumeMounts)
					}
					_, v := findEnvVar(c.Env, javaToolOptionsName)
					if v != javaToolOptionsArg {
						t.Fatalf("container[%d] JAVA_TOOL_OPTIONS=%q want %q", idx, v, javaToolOptionsArg)
					}
				}
			},
		},
		{
			name: "pod with existing initContainers — webhook appends, does not replace",
			pod: func() *corev1.Pod {
				p := newPod(corev1.Container{Name: "app", Image: "eclipse-temurin:17-jre"})
				p.Spec.InitContainers = []corev1.Container{
					{Name: "wait-for-db", Image: "busybox", Command: []string{"sleep", "1"}},
				}
				return p
			}(),
			javaIdx: []int{0},
			assertOut: func(t *testing.T, p *corev1.Pod) {
				if len(p.Spec.InitContainers) != 2 {
					t.Fatalf("expected 2 init containers (existing+agent), got %d", len(p.Spec.InitContainers))
				}
				if p.Spec.InitContainers[0].Name != "wait-for-db" {
					t.Fatalf("existing init container lost: %#v", p.Spec.InitContainers)
				}
				if p.Spec.InitContainers[1].Name != initContainerName {
					t.Fatalf("agent init container not appended: %#v", p.Spec.InitContainers)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			patchBytes, err := BuildPatch(tc.pod, tc.javaIdx, DefaultMutationConfig())
			if err != nil {
				t.Fatal(err)
			}
			if patchBytes == nil {
				t.Fatal("expected patch, got nil")
			}

			// Decode pod to JSON, apply patch, decode back.
			podJSON, err := json.Marshal(tc.pod)
			if err != nil {
				t.Fatal(err)
			}
			patch, err := jsonpatch.DecodePatch(patchBytes)
			if err != nil {
				t.Fatalf("DecodePatch failed: %v\npatch=%s", err, string(patchBytes))
			}
			mutatedJSON, err := patch.Apply(podJSON)
			if err != nil {
				t.Fatalf("patch.Apply failed: %v\npatch=%s", err, string(patchBytes))
			}
			var mutated corev1.Pod
			if err := json.Unmarshal(mutatedJSON, &mutated); err != nil {
				t.Fatalf("unmarshal mutated pod failed: %v", err)
			}
			tc.assertOut(t, &mutated)
		})
	}
}

// --- helpers ---

func newPod(containers ...corev1.Container) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "test-ns",
		},
		Spec: corev1.PodSpec{
			Containers: containers,
		},
	}
}
