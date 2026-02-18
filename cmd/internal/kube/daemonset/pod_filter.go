package daemonset

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PodFilter applies multi-layer filtering to determine which pods should be
// captured in daemonset discovery mode. Layers:
// 1. Namespace filtering (default excludes + user config)
// 2. Label/Annotation filtering (opt-in/opt-out)
// 3. Controller type filtering (skip Jobs, CronJobs, standalone pods)
type PodFilter struct {
	AgentPodName      string
	IncludeNamespaces map[string]bool
	ExcludeNamespaces map[string]bool
	IncludeLabels     map[string]string
	ExcludeLabels     map[string]string
}

// FilterResult is the outcome of evaluating a pod against the filter.
type FilterResult struct {
	ShouldCapture bool
	Reason        string
	ServiceName   string // Derived as namespace/workload-name
}

// NewPodFilter creates a PodFilter from the given configuration. The default
// excluded namespaces are always applied (merged with user-specified excludes).
// agentPodName is the name of the agent's own pod so it can be excluded from capture.
func NewPodFilter(
	agentPodName string,
	includeNamespaces []string,
	excludeNamespaces []string,
	includeLabels map[string]string,
	excludeLabels map[string]string,
) *PodFilter {
	includeNS := make(map[string]bool, len(includeNamespaces))
	for _, ns := range includeNamespaces {
		includeNS[ns] = true
	}

	excludeNS := make(map[string]bool, len(DefaultExcludedNamespaces)+len(excludeNamespaces))
	for _, ns := range DefaultExcludedNamespaces {
		excludeNS[ns] = true
	}
	for _, ns := range excludeNamespaces {
		excludeNS[ns] = true
	}

	return &PodFilter{
		AgentPodName:      agentPodName,
		IncludeNamespaces: includeNS,
		ExcludeNamespaces: excludeNS,
		IncludeLabels:     includeLabels,
		ExcludeLabels:     excludeLabels,
	}
}

// Evaluate runs the pod through all filter layers and returns a FilterResult.
func (f *PodFilter) Evaluate(pod corev1.Pod) FilterResult {
	// Layer 0: Skip the agent's own pod
	if f.AgentPodName != "" && pod.Name == f.AgentPodName {
		return FilterResult{ShouldCapture: false, Reason: "agent's own pod"}
	}

	// Layer 1: Namespace filtering
	if pass, reason := f.checkNamespace(pod.Namespace); !pass {
		return FilterResult{ShouldCapture: false, Reason: reason}
	}

	// Layer 2: Label and annotation filtering
	if pass, reason := f.checkLabelsAndAnnotations(pod); !pass {
		return FilterResult{ShouldCapture: false, Reason: reason}
	}

	// Layer 3: Controller type filtering
	if pass, reason := checkControllerType(pod); !pass {
		return FilterResult{ShouldCapture: false, Reason: reason}
	}

	serviceName := deriveServiceName(pod)
	return FilterResult{
		ShouldCapture: true,
		Reason:        "passed all filters",
		ServiceName:   serviceName,
	}
}

func (f *PodFilter) checkNamespace(ns string) (bool, string) {
	if f.ExcludeNamespaces[ns] {
		return false, fmt.Sprintf("excluded namespace: %s", ns)
	}
	if len(f.IncludeNamespaces) > 0 && !f.IncludeNamespaces[ns] {
		return false, fmt.Sprintf("namespace not in include list: %s", ns)
	}
	return true, ""
}

func (f *PodFilter) checkLabelsAndAnnotations(pod corev1.Pod) (bool, string) {
	// Opt-out annotation takes precedence
	if strings.EqualFold(pod.Annotations[AnnotationOptOut], "true") {
		return false, "explicit opt-out annotation"
	}
	if strings.EqualFold(pod.Annotations[AnnotationOptIn], "false") {
		return false, "insights-enabled set to false"
	}

	// Check exclude labels: if the pod matches any exclude label, skip it
	for k, v := range f.ExcludeLabels {
		if podVal, exists := pod.Labels[k]; exists && podVal == v {
			return false, fmt.Sprintf("matches exclude label %s=%s", k, v)
		}
	}

	// Check include labels: if specified, the pod must match all include labels
	if len(f.IncludeLabels) > 0 {
		for k, v := range f.IncludeLabels {
			podVal, exists := pod.Labels[k]
			if !exists || podVal != v {
				return false, fmt.Sprintf("does not match include label %s=%s", k, v)
			}
		}
	}

	return true, ""
}

// controllingOwner returns the owner reference with Controller==true.
// If none is marked as the controller, it falls back to the first reference.
// Returns nil when the pod has no owner references.
func controllingOwner(pod corev1.Pod) *metav1.OwnerReference {
	if len(pod.OwnerReferences) == 0 {
		return nil
	}
	for i := range pod.OwnerReferences {
		if pod.OwnerReferences[i].Controller != nil && *pod.OwnerReferences[i].Controller {
			return &pod.OwnerReferences[i]
		}
	}
	return &pod.OwnerReferences[0]
}

// checkControllerType filters by the pod's owner reference. Only long-running
// workloads (Deployment, StatefulSet, DaemonSet via ReplicaSet) are captured.
func checkControllerType(pod corev1.Pod) (bool, string) {
	owner := controllingOwner(pod)
	if owner == nil {
		return false, "standalone pod (no controller)"
	}

	switch owner.Kind {
	case "ReplicaSet", "StatefulSet", "DaemonSet":
		return true, ""
	case "Job", "CronJob":
		return false, "ephemeral workload (Job/CronJob)"
	default:
		return false, fmt.Sprintf("unsupported controller type: %s", owner.Kind)
	}
}

// deriveWorkloadType derives the workload type from the pod's controlling
// owner reference. For ReplicaSets (typically created by Deployments), it
// returns "Deployment". For other controller types, it returns the Kind directly.
func deriveWorkloadType(pod corev1.Pod) string {
	owner := controllingOwner(pod)
	if owner == nil {
		return ""
	}
	if owner.Kind == "ReplicaSet" {
		return "Deployment"
	}
	return owner.Kind
}

// deriveWorkloadName derives the workload name from the pod's controlling
// owner reference and labels, without the namespace prefix.
func deriveWorkloadName(pod corev1.Pod) string {
	owner := controllingOwner(pod)
	if owner != nil {
		workloadName := owner.Name
		if owner.Kind == "ReplicaSet" {
			if idx := strings.LastIndex(workloadName, "-"); idx > 0 {
				workloadName = workloadName[:idx]
			}
		}
		if workloadName != "" {
			return workloadName
		}
	}

	if name, ok := pod.Labels["app.kubernetes.io/name"]; ok {
		return name
	}
	if name, ok := pod.Labels["app"]; ok {
		return name
	}

	name := pod.Name
	if idx := strings.LastIndex(name, "-"); idx > 0 {
		return name[:idx]
	}
	return name
}

// deriveServiceName derives a service name from K8s pod metadata.
// Format: {namespace}/{workload-name}
func deriveServiceName(pod corev1.Pod) string {
	return pod.Namespace + "/" + deriveWorkloadName(pod)
}
