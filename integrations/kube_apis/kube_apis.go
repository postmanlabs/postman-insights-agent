package kube_apis

import (
	"os"
	"strings"

	"github.com/akitasoftware/go-utils/maps"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
	coreV1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// Env variable key for Kubernetes node name
	POSTMAN_INSIGHTS_K8S_NODE = "POSTMAN_INSIGHTS_K8S_NODE"
)

// KubeClient struct holds the Kubernetes clientset and pod informer.
type KubeClient struct {
	Clientset *kubernetes.Clientset
	AgentNode string
	AgentHost string

	PodInformer       cache.SharedIndexInformer
	podInformerStopCh chan struct{}
	podInformerDoneCh chan struct{}
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

	podInformer := newPodInformer(clientset, agentNodeName)

	kubeClient := KubeClient{
		Clientset: clientset,
		AgentNode: agentNodeName,
		AgentHost: agentHostName,

		PodInformer: podInformer,
	}

	kubeClient.podInformerStopCh = make(chan struct{})
	kubeClient.podInformerDoneCh = make(chan struct{})
	go func() {
		defer close(kubeClient.podInformerDoneCh)
		kubeClient.PodInformer.Run(kubeClient.podInformerStopCh)
	}()
	if err := waitForPodInformerSync(kubeClient.PodInformer, POD_INFORMER_SYNC_TIMEOUT); err != nil {
		kubeClient.Close()
		return KubeClient{}, errors.Wrap(err, "error syncing pod informer")
	}

	return kubeClient, nil
}

// Close stops the pod informer.
func (kc *KubeClient) Close() {
	if kc.podInformerStopCh != nil {
		close(kc.podInformerStopCh)
	}
	if kc.podInformerDoneCh != nil {
		<-kc.podInformerDoneCh
	}
}

// GetPodsInNode returns the names of all pods running in a given node
func (kc *KubeClient) GetPodsInAgentNode() ([]coreV1.Pod, error) {
	if kc.PodInformer == nil {
		return []coreV1.Pod{}, errors.New("pod informer is not initialized")
	}

	objects := kc.PodInformer.GetStore().List()
	pods := make([]coreV1.Pod, 0, len(objects))
	for _, object := range objects {
		pod, ok := object.(*coreV1.Pod)
		if ok {
			pods = append(pods, *pod.DeepCopy())
		}
	}
	return pods, nil
}

// GetPods returns a list of pods running on the agent node with the given names
func (kc *KubeClient) GetPodsByUIDs(podUIDs []types.UID) ([]coreV1.Pod, error) {
	if kc.PodInformer == nil {
		return []coreV1.Pod{}, errors.New("pod informer is not initialized")
	}

	var filteredPods []coreV1.Pod
	for _, uid := range podUIDs {
		objects, err := kc.PodInformer.GetIndexer().ByIndex("uid", string(uid))
		if err != nil || len(objects) == 0 {
			printer.Debugf("Pod not found with UID: %v\n", uid)
			continue
		}
		pod, ok := objects[0].(*coreV1.Pod)
		if ok {
			filteredPods = append(filteredPods, *pod.DeepCopy())
		}
	}

	if len(filteredPods) == 0 {
		return []coreV1.Pod{}, errors.Errorf("no pods found with UIDs: %v", podUIDs)
	}

	return filteredPods, nil
}

// FilterPodsByContainerImage filters a list of pods by the container image
// name. With negate false it returns the pods that run containerImage in at
// least one container; with negate true it returns the pods that do not run it
// at all.
//
// The match is decided per pod, not per container. Testing negate against each
// container in turn instead means a pod is selected the moment any single
// container disagrees with the image -- so with negate true, an
// app-plus-sidecar pod matched on its app container and was reported as not
// running the sidecar. Only a pod whose every container is containerImage was
// excluded, which in practice is nothing this is ever asked about.
func (kc *KubeClient) FilterPodsByContainerImage(pods []coreV1.Pod, containerImage string, negate bool) ([]coreV1.Pod, error) {
	var filteredPods []coreV1.Pod

	for _, pod := range pods {
		runsImage := false
		for _, container := range pod.Spec.Containers {
			if isImageEqual(containerImage, container.Image) {
				runsImage = true
				break
			}
		}
		if runsImage != negate {
			filteredPods = append(filteredPods, pod)
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
