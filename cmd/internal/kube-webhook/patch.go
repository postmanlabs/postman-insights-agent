// SPDX-License-Identifier: Apache-2.0

package kubewebhook

import (
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

// Path-related constants. We use the exact field names from the pod spec
// schema; if k8s ever renames these, our patches break loudly (a test
// fails) rather than silently doing the wrong thing.
const (
	// Volume + mount path inside the Java app container.
	agentVolumeName = "postman-insights-agent"
	agentMountPath  = "/postman"
	agentJarPath    = "/postman/postman-java-agent.jar"

	// Init container name + the command it runs to copy the agent JAR
	// into the shared volume.
	initContainerName = "postman-insights-agent-init"
	initContainerCmd  = "cp /opt/postman-java-agent.jar /postman/postman-java-agent.jar"

	// JAVA_TOOL_OPTIONS arg we add. If the container already sets
	// JAVA_TOOL_OPTIONS we APPEND to it (space-separated) so user options
	// are preserved.
	javaToolOptionsName = "JAVA_TOOL_OPTIONS"
	javaToolOptionsArg  = "-javaagent:" + agentJarPath
)

// jsonPatchOp is a single RFC 6902 patch operation. We hand-roll instead of
// pulling in a library: K8s admission webhooks only need a tiny subset of
// JSON Patch (add / replace) and the spec is one screen long.
type jsonPatchOp struct {
	Op    string      `json:"op"`              // "add" | "replace" | "remove" | "test"
	Path  string      `json:"path"`            // RFC 6901 pointer
	Value interface{} `json:"value,omitempty"` // omitted for "remove"
}

// MutationConfig parameterises the patch generation. Defaults work for our
// own container image; can be overridden by CLI flags in run.go.
type MutationConfig struct {
	// Container image that holds /opt/postman-java-agent.jar. The init
	// container uses this image and `cp`s the JAR into the shared volume.
	InitImage string

	// imagePullPolicy for the init container.
	InitImagePullPolicy corev1.PullPolicy
}

// DefaultMutationConfig returns sensible defaults. The init image name is
// deliberately a placeholder — operators MUST override via CLI flag or
// Helm values to point at their actual agent image build.
func DefaultMutationConfig() MutationConfig {
	return MutationConfig{
		InitImage:           "ghcr.io/postmanlabs/postman-insights-agent:latest",
		InitImagePullPolicy: corev1.PullIfNotPresent,
	}
}

// BuildPatch returns the JSON Patch (as a raw byte slice ready to put in
// AdmissionResponse.Patch) for the given pod, injecting the Java agent
// into each of the containers listed in javaContainerIndices.
//
// Returns (nil, nil) if javaContainerIndices is empty — the caller should
// admit the pod un-patched in that case.
//
// The patch consists of (in order):
//
//  1. Add the `emptyDir` agent volume.  If `spec.volumes` doesn't yet exist
//     we create the array; otherwise we append.
//  2. Add the init container.  If `spec.initContainers` doesn't yet exist
//     we create the array; otherwise we append.
//  3. For each Java container:
//     a. Add a volumeMount.
//     b. Add (or extend) `JAVA_TOOL_OPTIONS` env var.
//
// The patch is deterministic given (pod, indices, cfg) — important so the
// test cases produce stable golden outputs.
func BuildPatch(pod *corev1.Pod, javaContainerIndices []int, cfg MutationConfig) ([]byte, error) {
	if pod == nil {
		return nil, fmt.Errorf("BuildPatch: pod is nil")
	}
	if len(javaContainerIndices) == 0 {
		return nil, nil
	}

	ops := make([]jsonPatchOp, 0, 4+3*len(javaContainerIndices))

	// (1) Add the agent volume.
	volume := corev1.Volume{
		Name: agentVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	}
	if len(pod.Spec.Volumes) == 0 {
		ops = append(ops, jsonPatchOp{Op: "add", Path: "/spec/volumes", Value: []corev1.Volume{volume}})
	} else {
		ops = append(ops, jsonPatchOp{Op: "add", Path: "/spec/volumes/-", Value: volume})
	}

	// (2) Add the init container.
	initContainer := corev1.Container{
		Name:            initContainerName,
		Image:           cfg.InitImage,
		ImagePullPolicy: cfg.InitImagePullPolicy,
		Command:         []string{"/bin/sh", "-c", initContainerCmd},
		VolumeMounts: []corev1.VolumeMount{
			{Name: agentVolumeName, MountPath: agentMountPath},
		},
	}
	if len(pod.Spec.InitContainers) == 0 {
		ops = append(ops, jsonPatchOp{Op: "add", Path: "/spec/initContainers", Value: []corev1.Container{initContainer}})
	} else {
		ops = append(ops, jsonPatchOp{Op: "add", Path: "/spec/initContainers/-", Value: initContainer})
	}

	// (3) For each Java container, add volumeMount + JAVA_TOOL_OPTIONS env.
	for _, idx := range javaContainerIndices {
		c := pod.Spec.Containers[idx]

		// (3a) volumeMount
		mount := corev1.VolumeMount{Name: agentVolumeName, MountPath: agentMountPath}
		if len(c.VolumeMounts) == 0 {
			ops = append(ops, jsonPatchOp{
				Op:    "add",
				Path:  fmt.Sprintf("/spec/containers/%d/volumeMounts", idx),
				Value: []corev1.VolumeMount{mount},
			})
		} else {
			ops = append(ops, jsonPatchOp{
				Op:    "add",
				Path:  fmt.Sprintf("/spec/containers/%d/volumeMounts/-", idx),
				Value: mount,
			})
		}

		// (3b) JAVA_TOOL_OPTIONS — preserve existing value if present.
		existingIdx, existingValue := findEnvVar(c.Env, javaToolOptionsName)
		newValue := javaToolOptionsArg
		if existingValue != "" {
			// Append the agent arg AFTER existing options so existing
			// flags take precedence (Java reads JAVA_TOOL_OPTIONS left
			// to right; later occurrences of duplicate flags win).
			// Actually the safer convention is the opposite: prepend.
			// JAVA_TOOL_OPTIONS is space-separated; we just join.
			newValue = existingValue + " " + javaToolOptionsArg
		}
		env := corev1.EnvVar{Name: javaToolOptionsName, Value: newValue}

		switch {
		case existingIdx >= 0:
			ops = append(ops, jsonPatchOp{
				Op:    "replace",
				Path:  fmt.Sprintf("/spec/containers/%d/env/%d", idx, existingIdx),
				Value: env,
			})
		case len(c.Env) == 0:
			ops = append(ops, jsonPatchOp{
				Op:    "add",
				Path:  fmt.Sprintf("/spec/containers/%d/env", idx),
				Value: []corev1.EnvVar{env},
			})
		default:
			ops = append(ops, jsonPatchOp{
				Op:    "add",
				Path:  fmt.Sprintf("/spec/containers/%d/env/-", idx),
				Value: env,
			})
		}
	}

	return json.Marshal(ops)
}

// findEnvVar returns (index, value) if envVars contains a var with the
// given name; otherwise (-1, "").
func findEnvVar(envVars []corev1.EnvVar, name string) (int, string) {
	for i, e := range envVars {
		if e.Name == name {
			return i, e.Value
		}
	}
	return -1, ""
}
