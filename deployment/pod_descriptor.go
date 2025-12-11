package deployment

import (
	"strings"
	"time"

	coreV1 "k8s.io/api/core/v1"
)

// PodDescriptor contains comprehensive information about a Kubernetes pod
// for telemetry and lifecycle tracking purposes.
type PodDescriptor struct {
	// Core Identity
	PodUID    string `json:"pod_uid"`
	PodName   string `json:"pod_name"`
	Namespace string `json:"namespace"`
	NodeName  string `json:"node_name"`

	// Network
	PodIP  string `json:"pod_ip,omitempty"`
	HostIP string `json:"host_ip,omitempty"`

	// State
	Phase string `json:"phase"` // Running, Pending, Succeeded, Failed, Unknown

	// Containers
	Containers []ContainerDescriptor `json:"containers,omitempty"`

	// Resources (useful for capacity planning)
	ResourceRequests *ResourceSpec `json:"resource_requests,omitempty"`
	ResourceLimits   *ResourceSpec `json:"resource_limits,omitempty"`

	// Metadata
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`

	// Owner (Deployment, StatefulSet, DaemonSet, etc.)
	OwnerKind string `json:"owner_kind,omitempty"`
	OwnerName string `json:"owner_name,omitempty"`

	// Container env vars (with sensitive data filtering)
	// SECURITY: Sensitive keys are filtered out (PASSWORD, SECRET, TOKEN, etc.)
	EnvVars map[string]string `json:"env_vars,omitempty"`

	// Timestamps
	PodCreatedAt time.Time `json:"pod_created_at"`
	ObservedAt   time.Time `json:"observed_at"` // When agent observed it
}

// ContainerDescriptor contains information about a container within a pod.
type ContainerDescriptor struct {
	ContainerID  string `json:"container_id"`
	Name         string `json:"name"`
	Image        string `json:"image"`
	RestartCount int32  `json:"restart_count"`
	State        string `json:"state"` // Running, Waiting, Terminated
}

// ResourceSpec represents CPU and memory resource specifications.
type ResourceSpec struct {
	CPU    string `json:"cpu,omitempty"`    // e.g., "100m", "1"
	Memory string `json:"memory,omitempty"` // e.g., "128Mi", "1Gi"
}

// sensitiveEnvVarPatterns contains patterns that indicate sensitive environment variables.
// These patterns are matched case-insensitively against environment variable names.
var sensitiveEnvVarPatterns = []string{
	"PASSWORD",
	"SECRET",
	"TOKEN",
	"CREDENTIAL",
	"AUTH",
	"API_KEY",
	"APIKEY",
	"PRIVATE",
	"CERT",
	"PASSPHRASE",
	"ENCRYPTION",
	"SIGNING",
	"ACCESS_KEY",
	"SECRET_KEY",
}

// RedactedValue is the placeholder used for redacted sensitive values.
const RedactedValue = "[REDACTED]"

// isSensitiveEnvVar checks if an environment variable name contains sensitive patterns.
func isSensitiveEnvVar(name string) bool {
	upperName := strings.ToUpper(name)
	for _, pattern := range sensitiveEnvVarPatterns {
		if strings.Contains(upperName, pattern) {
			return true
		}
	}
	return false
}

// filterSensitiveEnvVars filters environment variables, redacting sensitive values.
// Key names are preserved but sensitive values are replaced with [REDACTED].
func filterSensitiveEnvVars(envVars map[string]string) map[string]string {
	if envVars == nil {
		return nil
	}

	filtered := make(map[string]string, len(envVars))
	for key, value := range envVars {
		if isSensitiveEnvVar(key) {
			filtered[key] = RedactedValue
		} else {
			filtered[key] = value
		}
	}
	return filtered
}

// getContainerState extracts the current state of a container from its status.
func getContainerState(status coreV1.ContainerStatus) string {
	if status.State.Running != nil {
		return "Running"
	}
	if status.State.Waiting != nil {
		return "Waiting"
	}
	if status.State.Terminated != nil {
		return "Terminated"
	}
	return "Unknown"
}

// extractContainerDescriptors extracts container information from pod status.
func extractContainerDescriptors(pod coreV1.Pod) []ContainerDescriptor {
	containers := make([]ContainerDescriptor, 0, len(pod.Status.ContainerStatuses))

	for _, status := range pod.Status.ContainerStatuses {
		// Find the corresponding container spec to get the image
		var image string
		for _, spec := range pod.Spec.Containers {
			if spec.Name == status.Name {
				image = spec.Image
				break
			}
		}

		containers = append(containers, ContainerDescriptor{
			ContainerID:  status.ContainerID,
			Name:         status.Name,
			Image:        image,
			RestartCount: status.RestartCount,
			State:        getContainerState(status),
		})
	}

	return containers
}

// extractResourceSpec extracts resource specifications from a ResourceList.
func extractResourceSpec(resources coreV1.ResourceList) *ResourceSpec {
	if len(resources) == 0 {
		return nil
	}

	spec := &ResourceSpec{}

	if cpu, ok := resources[coreV1.ResourceCPU]; ok {
		spec.CPU = cpu.String()
	}
	if memory, ok := resources[coreV1.ResourceMemory]; ok {
		spec.Memory = memory.String()
	}

	// Return nil if no relevant resources found
	if spec.CPU == "" && spec.Memory == "" {
		return nil
	}

	return spec
}

// extractAggregatedResources aggregates resource requests/limits from all containers.
func extractAggregatedResources(pod coreV1.Pod, getResources func(coreV1.Container) coreV1.ResourceList) *ResourceSpec {
	aggregated := coreV1.ResourceList{}

	for _, container := range pod.Spec.Containers {
		resources := getResources(container)
		for name, quantity := range resources {
			if existing, ok := aggregated[name]; ok {
				existing.Add(quantity)
				aggregated[name] = existing
			} else {
				aggregated[name] = quantity.DeepCopy()
			}
		}
	}

	return extractResourceSpec(aggregated)
}

// extractOwnerReference extracts the primary owner reference from a pod.
// Returns the first owner reference found, prioritizing controllers.
func extractOwnerReference(pod coreV1.Pod) (kind, name string) {
	if len(pod.OwnerReferences) == 0 {
		return "", ""
	}

	// First, look for a controller owner
	for _, ref := range pod.OwnerReferences {
		if ref.Controller != nil && *ref.Controller {
			return ref.Kind, ref.Name
		}
	}

	// Fall back to first owner reference
	ref := pod.OwnerReferences[0]
	return ref.Kind, ref.Name
}

// ExtractPodDescriptor creates a PodDescriptor from a Kubernetes Pod object
// and container environment variables retrieved from the CRI API.
//
// Parameters:
//   - pod: The Kubernetes Pod object containing pod metadata and status
//   - containerEnvVars: Environment variables from the container runtime (may be nil)
//
// Returns a PodDescriptor with all available information, including:
//   - Pod identity (UID, name, namespace, node)
//   - Network information (pod IP, host IP)
//   - Pod phase/state
//   - Container details (IDs, images, restart counts, states)
//   - Resource requests and limits (aggregated from all containers)
//   - Labels and annotations
//   - Owner reference (Deployment, StatefulSet, etc.)
//   - Filtered environment variables (sensitive values redacted)
//   - Timestamps
func ExtractPodDescriptor(pod coreV1.Pod, containerEnvVars map[string]string) *PodDescriptor {
	ownerKind, ownerName := extractOwnerReference(pod)

	descriptor := &PodDescriptor{
		// Core Identity
		PodUID:    string(pod.UID),
		PodName:   pod.Name,
		Namespace: pod.Namespace,
		NodeName:  pod.Spec.NodeName,

		// Network
		PodIP:  pod.Status.PodIP,
		HostIP: pod.Status.HostIP,

		// State
		Phase: string(pod.Status.Phase),

		// Containers
		Containers: extractContainerDescriptors(pod),

		// Resources (aggregated from all containers)
		ResourceRequests: extractAggregatedResources(pod, func(c coreV1.Container) coreV1.ResourceList {
			return c.Resources.Requests
		}),
		ResourceLimits: extractAggregatedResources(pod, func(c coreV1.Container) coreV1.ResourceList {
			return c.Resources.Limits
		}),

		// Metadata
		Labels:      pod.Labels,
		Annotations: pod.Annotations,

		// Owner
		OwnerKind: ownerKind,
		OwnerName: ownerName,

		// Environment variables (filtered for sensitive data)
		EnvVars: filterSensitiveEnvVars(containerEnvVars),

		// Timestamps
		ObservedAt: time.Now(),
	}

	// Set pod creation time if available
	if !pod.CreationTimestamp.IsZero() {
		descriptor.PodCreatedAt = pod.CreationTimestamp.Time
	}

	return descriptor
}
