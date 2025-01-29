package kube_apis

import (
	"context"
	"fmt"
	"log"
	"strings"

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
}

// NewKubeClient initializes a new Kubernetes client
func NewKubeClient() KubeClient {
	// Setup Kubernetes client
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fallback to kubeconfig
		kubeconfig := clientcmd.NewDefaultClientConfigLoadingRules().GetDefaultFilename()
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.Fatalf("Error building kubeconfig: %v", err)
		}
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Error creating clientset: %v", err)
	}

	kubeClient := KubeClient{
		Clientset: clientset,
	}

	// Initialize event watcher
	kubeClient.initEventWatcher()

	return kubeClient
}

// TearDown stops the event watcher
func (kc *KubeClient) TearDown() {
	kc.EventWatch.Stop()
}

// initEventWatcher creates a new go-channel to listen for all events in the cluster
func (kc *KubeClient) initEventWatcher() {
	watcher, err := kc.Clientset.CoreV1().Pods("").Watch(context.Background(), metaV1.ListOptions{
		Watch: true,
	})
	if err != nil {
		log.Fatalf("Error creating watcher: %v", err)
	}

	kc.EventWatch = watcher
}

// GetPodContainerImages returns the container images of a given pod
func (kc *KubeClient) GetPodContainerImages(podName string) []string {
	pod, err := kc.Clientset.CoreV1().Pods("default").Get(context.Background(), podName, metaV1.GetOptions{})
	if err != nil {
		log.Fatalf("Error getting pod: %v", err)
	}

	var containerImages []string
	for _, container := range pod.Spec.Containers {
		containerImages = append(containerImages, container.Image)
	}

	return containerImages
}

// GetMainContainerUUID returns the UUID of the main container of a given pod
func (kc *KubeClient) GetMainContainerUUID(podName string) (string, error) {
	pod, err := kc.Clientset.CoreV1().Pods("default").Get(context.Background(), podName, metaV1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("error getting pod: %v", err)
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
