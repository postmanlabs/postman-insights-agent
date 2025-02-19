package cri_apis

import (
	"context"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const (
	// Env variable key for CRI endpoint
	POSTMAN_INSIGHTS_CRI_ENDPOINT = "POSTMAN_INSIGHTS_CRI_ENDPOINT"

	// Context timeout for all CRI operations
	connectionTimeout = 5 * time.Second

	// Default containerd runtime endpoint
	containerdCRIEndpoint = "unix:///run/containerd/containerd.sock"
)

// CriClient struct holds the runtime service client
type CriClient struct {
	runtimeService *remoteRuntimeService
}

// NewCRIClient initializes a new CRI client
func NewCRIClient() (*CriClient, error) {
	var (
		service *remoteRuntimeService
		err     error
	)

	criEndpoint := os.Getenv(POSTMAN_INSIGHTS_CRI_ENDPOINT)
	if criEndpoint != "" {
		service, err = newRemoteRuntimeService(criEndpoint, connectionTimeout)
		if err != nil {
			return nil, err
		}
	} else {
		printer.Infof("No CRI endpoint provided, trying default CRI endpoint\n")
		service, err = newRemoteRuntimeService(containerdCRIEndpoint, connectionTimeout)
		if err != nil {
			printer.Errorf("Failed to connect to %s: %v\n", containerdCRIEndpoint, err)
		}
	}

	if service == nil {
		return nil, errors.New("failed to connect to CRI endpoint")
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

	// the ContainerStatusResponse.Info has a generic map of strings[stringifiedJson], which should be in JSON format.
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

	return "", errors.New("network namespace not found")
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
