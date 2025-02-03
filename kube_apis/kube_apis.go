package kube_apis

import (
	"context"
	"fmt"
	"os"
	"strings"

	coreV1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// KubeClient struct holds the Kubernetes clientset and event watcher
type KubeClient struct {
	Clientset  *kubernetes.Clientset
	EventWatch watch.Interface
	AgentNode  string
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
			return KubeClient{}, fmt.Errorf("error building kubeconfig: %v", err)
		}
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return KubeClient{}, fmt.Errorf("error creating clientset: %v", err)
	}

	agentNodeName := os.Getenv("POSTMAN_K8S_NODE")
	if agentNodeName == "" {
		return KubeClient{}, fmt.Errorf("POSTMAN_K8S_NODE environment variable not set")
	}

	kubeClient := KubeClient{
		Clientset: clientset,
		AgentNode: agentNodeName,
	}

	// Initialize event watcher
	err = kubeClient.initEventWatcher()
	if err != nil {
		return KubeClient{}, err
	}

	return kubeClient, nil
}

// TearDown stops the event watcher
func (kc *KubeClient) TearDown() {
	kc.EventWatch.Stop()
}

// initEventWatcher creates a new go-channel to listen for all events in the cluster
func (kc *KubeClient) initEventWatcher() error {
	watcher, err := kc.Clientset.CoreV1().Pods("").Watch(context.Background(), metaV1.ListOptions{
		Watch: true,
	})
	if err != nil {
		return fmt.Errorf("error creating watcher: %v", err)
	}

	kc.EventWatch = watcher
	return nil
}

func (kc *KubeClient) getPod(podName string) (coreV1.Pod, error) {
	fieldSelector := fmt.Sprintf("metadata.name=%s", podName)
	pods, err := kc.Clientset.CoreV1().Pods("").List(context.Background(), metaV1.ListOptions{
		FieldSelector: fieldSelector,
	})
	if err != nil {
		return coreV1.Pod{}, fmt.Errorf("error getting pods: %v", err)
	}
	if len(pods.Items) == 0 {
		return coreV1.Pod{}, fmt.Errorf("pod not found: %s", podName)
	}
	return pods.Items[0], nil
}

// GetPodContainerImages returns the container images of a given pod
func (kc *KubeClient) GetPodContainerImages(podName string) ([]string, error) {
	pod, err := kc.getPod(podName)
	if err != nil {
		return nil, err
	}

	var containerImages []string
	for _, container := range pod.Spec.Containers {
		containerImages = append(containerImages, container.Image)
	}

	return containerImages, nil
}

// GetMainContainerUUID returns the UUID of the main container of a given pod
func (kc *KubeClient) GetMainContainerUUID(podName string) (string, error) {
	pod, err := kc.getPod(podName)
	if err != nil {
		return "", err
	}

	if len(pod.Status.ContainerStatuses) > 0 {
		containerID := pod.Status.ContainerStatuses[0].ContainerID

		// Extract UUID from the container ID
		parts := strings.Split(containerID, "://")
		if len(parts) == 2 {
			return parts[1], nil
		} else {
			return "", fmt.Errorf("invalid container ID: %s", containerID)
		}
	}

	return "", fmt.Errorf("no container statuses found for pod: %s", podName)
}

// GetPodsInNode returns the names of all pods running in a given node
func (kc *KubeClient) GetPodsInNode(nodeName string) ([]string, error) {
	fieldSelector := fmt.Sprintf("spec.nodeName=%s", nodeName)
	pods, err := kc.Clientset.CoreV1().Pods("").List(context.Background(), metaV1.ListOptions{
		FieldSelector: fieldSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("error getting pods: %v", err)
	}

	var podNames []string
	for _, pod := range pods.Items {
		podNames = append(podNames, pod.Name)
	}

	return podNames, nil
}

// GetPodStatus returns the status of a given pod
func (kc *KubeClient) GetPodStatus(podName string) (string, error) {
	pod, err := kc.getPod(podName)
	if err != nil {
		return "", err
	}

	return string(pod.Status.Phase), nil
}
