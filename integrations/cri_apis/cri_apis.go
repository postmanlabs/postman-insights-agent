package cri_apis

import (
	"fmt"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const containerdCRIEndpoint = "unix:///var/run/containerd/containerd.sock"
const CRIOEndpoint = "unix:///var/run/crio/crio.sock"

// grpc library default is 4MB for message size
const maxMsgSize = 1024 * 1024 * 4

type NetworkNamespace string

type ContainerInfo struct {
	// Container Info struct
}

type CriClient struct {
	// CRI Client struct
}

// Constructor to init the client
func NewCRIClient() (*CriClient, error) {
	// Set up connection to CRI
	conn, err := grpc.Dial(
		containerdCRIEndpoint, // CRI Endpoint
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMsgSize)),
	)
	if err != nil {
		log.Fatalf("Failed to connect to CRI endpoint: %v", err)
	}
	defer conn.Close()

	// Create runtime service client
	// TODO: assign runtime to CriClient struct
	_ = runtime.NewRuntimeServiceClient(conn)

	return &CriClient{}, nil
}

// Function to inspect the container with the given ID. This will be the internal function ??
func (cc *CriClient) inspectContainer(containerID string) (ContainerInfo, error) {
	// Inspect the container
	return ContainerInfo{}, fmt.Errorf("not implemented")
}

// Separate functions to get network namespace and environment variables of a container
// Function to get the network namespace of a container
func (cc *CriClient) GetNetworkNamespace(containerID string) (NetworkNamespace, error) {
	// Get the network namespace
	return "", fmt.Errorf("not implemented")
}

// Function to get the environment variables of a container
func (cc *CriClient) GetEnvVars(containerID string) (map[string]string, error) {
	// Get the environment variables
	return nil, fmt.Errorf("not implemented")
}
