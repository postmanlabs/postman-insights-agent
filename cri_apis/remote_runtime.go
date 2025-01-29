package cri_apis

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// This is the custom implementation of https://github.com/kubernetes/cri-client for interacting with CRI
// Most of the functions written here are taken from the original implementation and modified to fit the needs of the agent
// The original implementation is not used because it is not compatible with the agent's go version

const (
	// grpc library default is 4MB for message size
	maxMsgSize = 1024 * 1024 * 4
)

func newRemoteRuntimeServiceClient(endpoint string, connectionTimeout time.Duration) (runtime.RuntimeServiceClient, error) {
	addr, dialer, err := getAddressAndDialer(endpoint)
	if err != nil {
		return nil, err
	}

	var dialOpts []grpc.DialOption
	dialOpts = append(dialOpts,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithAuthority("localhost"),
		grpc.WithContextDialer(dialer),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMsgSize)))

	conn, err := grpc.NewClient(addr, dialOpts...)
	if err != nil {
		return nil, err
	}

	runtimeClient := runtime.NewRuntimeServiceClient(conn)

	// Validate the connection by checking the CRI v1 runtime API version
	if _, err := runtimeClient.Version(context.Background(), &runtime.VersionRequest{}); err != nil {
		return nil, fmt.Errorf("error validating CRI v1 runtime API for endpoint %q: %w", endpoint, err)
	}

	return runtimeClient, nil
}
