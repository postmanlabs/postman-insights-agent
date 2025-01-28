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

type KubeClient struct {
	// Kube Client struct
	Clientset *kubernetes.Clientset

	// Channel to listen to for events
	EventWatch watch.Interface
}

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

	kubeClient.initEventWatcher()

	return kubeClient
}

func (kc *KubeClient) TearDown() {
	// Stop the event watch
	kc.EventWatch.Stop()
}

// This watcher will create a new go-channel which will listen for all events in the cluster
func (kc *KubeClient) initEventWatcher() {
	// Create a watch for pod events
	watcher, err := kc.Clientset.CoreV1().Pods("").Watch(context.Background(), metaV1.ListOptions{
		Watch: true,
	})
	if err != nil {
		log.Fatalf("Error creating watcher: %v", err)
	}

	kc.EventWatch = watcher
}

// Function to return the go-channel to listen to for getting events
func (kc *KubeClient) GetEventWatcher() (watch.Interface, error) {
	// Return the event watch channel
	return nil, fmt.Errorf("not implemented")
}

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

// Function to get main container's uuid in a pod
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
