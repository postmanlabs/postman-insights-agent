package cri_apis

import (
	"context"
	"fmt"
	"time"

	"github.com/postmanlabs/postman-insights-agent/printer"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const (
	// Context timeout for all CRI operations
	connectionTimeout = 2 * time.Second
)

// Default runtime endpoints to try connecting to if no endpoint is provided
var defaultRuntimeEndpoints = []string{"unix:///run/containerd/containerd.sock", "unix:///run/crio/crio.sock", "unix:///var/run/cri-dockerd.sock"}

// CriClient struct holds the runtime service client
type CriClient struct {
	runtimeService *remoteRuntimeService
}

// NewCRIClient initializes a new CRI client
func NewCRIClient(criEndpoint string) (*CriClient, error) {
	var (
		service *remoteRuntimeService
		err     error
	)

	if criEndpoint != "" {
		service, err = newRemoteRuntimeService(criEndpoint, connectionTimeout)
		if err != nil {
			return nil, err
		}
	} else {
		printer.Infof("No CRI endpoint provided, trying default endpoints\n")
		// Fallback mechanism to try connecting to default endpoints
		// It will slow down the agent startup since each connection will take
		// some time before timing out.
		for _, endpoint := range defaultRuntimeEndpoints {
			service, err = newRemoteRuntimeService(endpoint, connectionTimeout)
			if err != nil {
				printer.Debugf("Failed to connect to %s: %v\n", endpoint, err)
				continue
			} else {
				printer.Debugf("Connected to %s\n", endpoint)
				break
			}
		}
	}

	if service == nil {
		return nil, fmt.Errorf("failed to connect to CRI runtime")
	}

	criClient := CriClient{
		runtimeService: service,
	}

	return &criClient, nil
}

// inspectContainer inspects the container with the given ID
func (cc *CriClient) inspectContainer(containerID string) (ContainerInfo, error) {
	containerStatusRequest := &runtime.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true, // Needed to get info object
	}

	ctx, cancel := context.WithTimeout(context.Background(), cc.runtimeService.timeout)
	defer cancel()

	// Inspect the container
	resp, err := cc.runtimeService.runtimeClient.ContainerStatus(ctx, containerStatusRequest)
	if err != nil {
		return ContainerInfo{}, err
	}

	containerInfo, err := convertContainerInfo(resp.Info)
	if err != nil {
		return ContainerInfo{}, err
	}

	return containerInfo, nil
}

// GetNetworkNamespace returns the network namespace of a given container
func (cc *CriClient) GetNetworkNamespace(containerID string) (string, error) {
	containerInfo, err := cc.inspectContainer(containerID)
	if err != nil {
		return "", err
	}

	for _, namespace := range containerInfo.RuntimeSpec.Linux.Namespaces {
		if namespace.Type == "network" {
			return namespace.Path, nil
		}
	}

	return "", fmt.Errorf("network namespace not found")
}

// GetEnvVars returns the environment variables of a given container
func (cc *CriClient) GetEnvVars(containerID string) (map[string]string, error) {
	containerInfo, err := cc.inspectContainer(containerID)
	if err != nil {
		return nil, err
	}

	envVars := make(map[string]string)
	for _, keyValueObj := range containerInfo.Config.Envs {
		envVars[keyValueObj.Key] = keyValueObj.Value
	}

	return envVars, nil
}
