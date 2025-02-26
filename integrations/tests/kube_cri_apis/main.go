// This test file is designed to be run only within a Kubernetes pod with the required deployment.yaml configuration.
// The deployment file creates the required service account, cluster role binding and pod with the necessary permissions
// to interact with the Kubernetes and Container Runtime Interface (CRI) APIs.
//
// It performs the following operations:
// 1. Initializes a KubeClient to interact with the Kubernetes API.
// 2. Retrieves the list of pods in the agent node.
// 3. Filters the pods by a specific container image.
// 4. Retrieves detailed information and status of a specific pod.
// 5. Extracts the main container UUID from the pod.
// 6. Initializes a CriClient to interact with the Container Runtime Interface (CRI) API.
// 7. Retrieves the network namespace and environment variables of the container using its UUID.
//
// Note: Don't forget to remove the resources created by the deployment file after running the test.

package main

import (
	"encoding/json"
	"fmt"

	"github.com/postmanlabs/postman-insights-agent/integrations/cri_apis"
	"github.com/postmanlabs/postman-insights-agent/integrations/kube_apis"
	"github.com/postmanlabs/postman-insights-agent/printer"
	coreV1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
)

func k8s_watcher(kubeClient kube_apis.KubeClient) {
	// Watch for pod events
	for event := range kubeClient.PodEventWatch.ResultChan() {
		printer.Infof("Received event: %v\n", event.Type)
		switch event.Type {
		case watch.Added, watch.Deleted:
			if e, ok := event.Object.(*coreV1.Event); ok {
				jsonData, err := json.Marshal(e)
				if err != nil {
					printer.Errorf("Failed to marshal event data: %v\n", err)
					continue
				}
				printer.Infof("Event data: %s\n", string(jsonData))
			}
		default:
			printer.Infof("Unhandled event type: %v\n", event.Type)
		}
	}
}

func k8s_funcs(kubeClient kube_apis.KubeClient) (string, error) {
	// GetPodsInNode
	podsInNode, err := kubeClient.GetPodsInAgentNode()
	if err != nil {
		return "", fmt.Errorf("failed to get pods in node: %v", err)
	}
	if len(podsInNode) == 0 {
		return "", fmt.Errorf("no pods found in node: %v", kubeClient.AgentNode)
	}
	printer.Infof("Found %d pods in node: %v\n", len(podsInNode), kubeClient.AgentNode)

	// Filter pods by container image
	filteredPods, err := kubeClient.FilterPodsByContainerImage(podsInNode, "public.ecr.aws/postman/postman-insights-agent:latest", false)
	if err != nil {
		return "", fmt.Errorf("failed to filter pods by container image: %v", err)
	}
	if len(filteredPods) == 0 {
		return "", fmt.Errorf("no pods found with container image")
	}
	printer.Infof("Found %d pods with container image\n", len(filteredPods))
	podNames := ""
	for _, pod := range filteredPods {
		podNames += pod.Name + " "
	}
	printer.Infof("Pod Names: %s\n", podNames)

	// Get single pod info
	pods, err := kubeClient.GetPodsByUIDs([]types.UID{podsInNode[0].UID})
	if err != nil {
		return "", fmt.Errorf("failed to get pod info: %v", err)
	}
	if len(pods) == 0 {
		return "", fmt.Errorf("no pods found with names: %v", podsInNode[0].Name)
	}
	pod := pods[0]

	// GetPodStatus
	podStatuses, err := kubeClient.GetPodsStatusByUIDs([]types.UID{pod.UID})
	if err != nil {
		return "", fmt.Errorf("failed to get pod status: %v", err)
	}
	printer.Infof("Pod Status: %s\n", podStatuses)

	// Get Main Container UUID
	containerUUIDs, err := kubeClient.GetContainerUUIDs(pod)
	if err != nil {
		return "", fmt.Errorf("failed to get main container UUID: %v", err)
	}
	printer.Infof("Container UUIDs: %s\n", containerUUIDs)

	return containerUUIDs[0], nil
}

func cri_funcs(containerUUID string) error {
	// Initialize CriClient
	criClient, err := cri_apis.NewCRIClient()
	if err != nil {
		return fmt.Errorf("failed to create CriClient: %v", err)
	}

	// GetNetworkNamespace
	networkNamespace, err := criClient.GetNetworkNamespace(containerUUID)
	if err != nil {
		return fmt.Errorf("failed to get network namespace: %v", err)
	}
	printer.Infof("Network Namespace: %s\n", networkNamespace)

	// GetEnvVars
	envVars, err := criClient.GetEnvVars(containerUUID)
	if err != nil {
		return fmt.Errorf("failed to get environment variables: %v", err)
	}
	printer.Infof("Environment Variables: %v\n", envVars)

	return nil
}

func main() {
	// Initialize KubeClient
	kubeClient, err := kube_apis.NewKubeClient()
	if err != nil {
		printer.Errorf("Failed to create KubeClient: %v\n", err)
		return
	}
	defer kubeClient.Close()

	// Call k8s_funcs
	containerUUID, err := k8s_funcs(kubeClient)
	if err != nil {
		printer.Errorf("Error from k8s_funcs: %v\n", err)
	}

	// Call cri_funcs
	if containerUUID == "" {
		printer.Infoln("Container UUID not found, skipping CRI functions...")
	} else {
		err = cri_funcs(containerUUID)
		if err != nil {
			printer.Errorf("Error from cri_funcs: %v\n", err)
		}
	}

	// Watch for pod events
	k8s_watcher(kubeClient)
}
