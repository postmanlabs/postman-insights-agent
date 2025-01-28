package kube_apis

import (
	"fmt"
	"log"

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

// This watcher will create a new go-channel which will only forward the events belonging to the specific node
// We can get the node from daemonset's node. But how will it help?
func (kc *KubeClient) initEventWatcher() {
	// Not implemented
}

// Function to return the go-channel to listen to for getting events
func (kc *KubeClient) GetEventWatcher() (watch.Interface, error) {
	// Return the event watch channel
	return nil, fmt.Errorf("not implemented")
}

func (kc *KubeClient) GetPodContainerImages(podName string) []string {
	return nil
}

// Function to get main container's uuid in a pod
func (kc *KubeClient) GetMainContainerUUID(podName string) (string, error) {
	return "", fmt.Errorf("not implemented")
}
