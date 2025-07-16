package kube_apis

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/akitasoftware/go-utils/maps"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
	coreV1 "k8s.io/api/core/v1"
	kubeErrs "k8s.io/apimachinery/pkg/api/errors"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	watchTool "k8s.io/client-go/tools/watch"
)

const (
	// Env variable key for Kubernetes node name
	POSTMAN_INSIGHTS_K8S_NODE = "POSTMAN_INSIGHTS_K8S_NODE"
)

// An exponential retry backoff policy that results in approximately 24 retires over a 24 hour period.
var retry = wait.Backoff{
	Duration: 10 * time.Millisecond,
	Factor:   2.0,
	Jitter:   0.1,
	Steps:    24,
	Cap:      24 * time.Hour,
}

// KubeClient struct holds the Kubernetes clientset and event watcher
type KubeClient struct {
	Clientset     *kubernetes.Clientset
	PodEventWatch *watchTool.RetryWatcher
	AgentNode     string
	AgentHost     string
}

// NewKubeClient initializes a new Kubernetes client
func NewKubeClient() (KubeClient, error) {
	// Setup Kubernetes client
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fallback to kubeconfig
		kubeconfig := clientcmd.NewDefaultClientConfigLoadingRules().GetDefaultFilename()
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return KubeClient{}, errors.Wrap(err, "error building kubeconfig")
		}
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return KubeClient{}, errors.Wrap(err, "error creating clientset")
	}

	agentNodeName := os.Getenv(POSTMAN_INSIGHTS_K8S_NODE)
	if agentNodeName == "" {
		return KubeClient{}, errors.New(POSTMAN_INSIGHTS_K8S_NODE + " environment variable not set")
	}

	agentHostName, err := os.Hostname()
	if err != nil {
		return KubeClient{}, errors.Wrap(err, "error getting hostname")
	}

	kubeClient := KubeClient{
		Clientset: clientset,
		AgentNode: agentNodeName,
		AgentHost: agentHostName,
	}

	// Initialize event watcher
	err = kubeClient.initPodsEventsWatcher()
	if err != nil {
		return KubeClient{}, err
	}

	return kubeClient, nil
}

// Close stops the event watcher
func (kc *KubeClient) Close() {
	kc.PodEventWatch.Stop()
}

// initPodsEventsWatcher creates a new go-channel to listen for pod events in the cluster
func (kc *KubeClient) initPodsEventsWatcher() error {
	// Fetch own pod details and get the ResourceVersion
	podsResourceVersion := ""
	err := wait.ExponentialBackoff(retry, func() (bool, error) {
		fieldSelector := fmt.Sprintf("metadata.name=%s", kc.AgentHost)
		pods, err := kc.Clientset.CoreV1().Pods("").List(context.Background(), metaV1.ListOptions{
			FieldSelector: fieldSelector,
		})
		if err != nil {
			if kubeErrs.IsTimeout(err) {
				printer.Warningf("request to get agent pod details timeout, retrying...")
				return false, nil
			}
			return false, err
		}
		podsResourceVersion = pods.ResourceVersion
		return true, nil
	})
	if err != nil {
		return errors.Wrap(err, "error getting own pod details")
	}

	// Create a watcher for pod events
	// Here ResourceVersion is set to the pod's ResourceVersion to watch events after the pod's creation
	fieldSelector := fmt.Sprintf("spec.nodeName=%s", kc.AgentNode)
	retryWatcher, err := watchTool.NewRetryWatcher(podsResourceVersion, &cache.ListWatch{
		ListFunc: func(options metaV1.ListOptions) (runtime.Object, error) {
			options.FieldSelector = fieldSelector
			return kc.Clientset.CoreV1().Pods("").List(context.Background(), options)
		},
		WatchFunc: func(options metaV1.ListOptions) (watch.Interface, error) {
			options.FieldSelector = fieldSelector
			return kc.Clientset.CoreV1().Pods("").Watch(context.Background(), options)
		},
	})
	if err != nil {
		return errors.Wrap(err, "error creating watcher")
	}

	kc.PodEventWatch = retryWatcher
	return nil
}

// GetPodsInNode returns the names of all pods running in a given node
func (kc *KubeClient) GetPodsInAgentNode() ([]coreV1.Pod, error) {
	var pods []coreV1.Pod
	err := wait.ExponentialBackoff(retry, func() (bool, error) {
		fieldSelector := fmt.Sprintf("spec.nodeName=%s", kc.AgentNode)
		podList, err := kc.Clientset.CoreV1().Pods("").List(context.Background(), metaV1.ListOptions{
			FieldSelector: fieldSelector,
		})
		if err != nil {
			if kubeErrs.IsTimeout(err) {
				printer.Warningf("request to get pods in agent node timeout, retrying...")
			}
			return false, err
		}
		pods = podList.Items
		return true, nil
	})
	if err != nil {
		return []coreV1.Pod{}, errors.Wrap(err, "error getting pods")
	}

	return pods, nil
}

// GetPods returns a list of pods running on the agent node with the given names
func (kc *KubeClient) GetPodsByUIDs(podUIDs []types.UID) ([]coreV1.Pod, error) {
	pods, err := kc.GetPodsInAgentNode()
	if err != nil {
		return []coreV1.Pod{}, err
	}
	if len(pods) == 0 {
		return []coreV1.Pod{}, errors.Errorf("no pods in node: %s", kc.AgentNode)
	}

	podMap := maps.NewMap[types.UID, coreV1.Pod]()
	for _, pod := range pods {
		podMap.Put(pod.UID, pod)
	}

	var filteredPods []coreV1.Pod
	for _, uid := range podUIDs {
		pod, ok := podMap.Get(uid).Get()
		if !ok {
			printer.Debugf("Pod not found with UID: %v\n", uid)
			continue
		}
		filteredPods = append(filteredPods, pod)
	}

	if len(filteredPods) == 0 {
		return []coreV1.Pod{}, errors.Errorf("no pods found with UIDs: %v", podUIDs)
	}

	return filteredPods, nil
}

// FilterPodsByContainerImage filters a list of pods by the container image name
func (kc *KubeClient) FilterPodsByContainerImage(pods []coreV1.Pod, containerImage string, negate bool) ([]coreV1.Pod, error) {
	var filteredPods []coreV1.Pod

	for _, pod := range pods {
		for _, container := range pod.Spec.Containers {
			if isImageEqual(containerImage, container.Image) != negate {
				filteredPods = append(filteredPods, pod)
				break
			}
		}
	}

	return filteredPods, nil
}

// GetContainerUUIDs returns the UUIDs of all containers in a given pod
func (kc *KubeClient) GetContainerUUIDs(pod coreV1.Pod) ([]string, error) {
	var containerUUIDs []string

	for _, containerStatus := range pod.Status.ContainerStatuses {
		containerID := containerStatus.ContainerID

		// Extract UUID from the container ID
		parts := strings.Split(containerID, "://")
		if len(parts) == 2 {
			containerUUIDs = append(containerUUIDs, parts[1])
		} else {
			printer.Debugf("invalid container ID: %s\n", containerID)
		}
	}

	return containerUUIDs, nil
}

// GetPodsStatus returns the statuses for list of pods
func (kc *KubeClient) GetPodsStatusByUIDs(podUIDs []types.UID) (maps.Map[types.UID, coreV1.PodPhase], error) {
	statuses := maps.NewMap[types.UID, coreV1.PodPhase]()

	pods, err := kc.GetPodsByUIDs(podUIDs)
	if err != nil {
		return statuses, err
	}

	for _, pod := range pods {
		statuses[pod.UID] = pod.Status.Phase
	}

	return statuses, nil
}
