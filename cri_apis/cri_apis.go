package cri_apis

import (
	"context"
	"fmt"
	"time"

	"github.com/postmanlabs/postman-insights-agent/printer"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const (
	connectionTimeout = 2 * time.Second
)

var defaultRuntimeEndpoints = []string{"unix:///run/containerd/containerd.sock", "unix:///run/crio/crio.sock", "unix:///var/run/cri-dockerd.sock"}

// CriClient struct holds the runtime service client
type CriClient struct {
	runtime runtime.RuntimeServiceClient
}

// NewCRIClient initializes a new CRI client
func NewCRIClient(criEndpoint string) (*CriClient, error) {
	var (
		client runtime.RuntimeServiceClient
		err    error
	)

	if criEndpoint != "" {
		client, err = newRemoteRuntimeServiceClient(criEndpoint, connectionTimeout)
		if err != nil {
			return nil, err
		}
	} else {
		printer.Infof("No CRI endpoint provided, trying default endpoints")
		// Fallback mechanism to try connecting to default endpoints
		// It will slow down the agent startup since each connection will take
		// some time before timing out.
		for _, endpoint := range defaultRuntimeEndpoints {
			client, err = newRemoteRuntimeServiceClient(endpoint, connectionTimeout)
			if err != nil {
				printer.Infof("Failed to connect to %s: %v", endpoint, err)
				continue
			} else {
				printer.Infof("Connected to %s", endpoint)
				break
			}
		}
	}

	criClient := CriClient{
		runtime: client,
	}

	return &criClient, nil
}

// inspectContainer inspects the container with the given ID
func (cc *CriClient) inspectContainer(containerID string) (ContainerInfo, error) {
	containerStatusRequest := &runtime.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true, // Needed to get info object
	}
	// Inspect the container
	resp, err := cc.runtime.ContainerStatus(context.Background(), containerStatusRequest)
	if err != nil {
		return ContainerInfo{}, err
	}
	printer.Debugf("Container Response: %v", resp)

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
