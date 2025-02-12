package cri_apis

import (
	"context"
	"time"

	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// This is the custom implementation of https://github.com/kubernetes/cri-client for interacting with CRI
// Most of the functions written here are taken from the original implementation and modified to fit the needs of the agent
// The original implementation is not used because it is not compatible with the agent's go version

const (
	// connection parameters
	maxBackoffDelay      = 3 * time.Second
	baseBackoffDelay     = 100 * time.Millisecond
	minConnectionTimeout = 5 * time.Second
)

// remoteRuntimeService is a gRPC implementation of internalapi.RuntimeService.
type remoteRuntimeService struct {
	timeout       time.Duration
	runtimeClient runtimeapi.RuntimeServiceClient
}

// NewRemoteRuntimeService creates a new internalapi.RuntimeService.
func newRemoteRuntimeService(endpoint string, connectionTimeout time.Duration) (*remoteRuntimeService, error) {
	addr, dialer, err := getAddressAndDialer(endpoint)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), connectionTimeout)
	defer cancel()

	var dialOpts []grpc.DialOption
	dialOpts = append(dialOpts,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithAuthority("localhost"),
		grpc.WithContextDialer(dialer))

	connParams := grpc.ConnectParams{
		Backoff: backoff.DefaultConfig,
	}
	connParams.MinConnectTimeout = minConnectionTimeout
	connParams.Backoff.BaseDelay = baseBackoffDelay
	connParams.Backoff.MaxDelay = maxBackoffDelay
	dialOpts = append(dialOpts,
		grpc.WithConnectParams(connParams),
	)

	conn, err := grpc.DialContext(ctx, addr, dialOpts...)
	if err != nil {
		return nil, err
	}

	service := &remoteRuntimeService{
		timeout: connectionTimeout,
	}

	if err := service.validateServiceConnection(ctx, conn, endpoint); err != nil {
		return nil, errors.Wrap(err, "validate service connection: %w")
	}

	return service, nil
}

// validateServiceConnection tries to connect to the remote runtime service by
// using the CRI v1 API version and fails if that's not possible.
func (r *remoteRuntimeService) validateServiceConnection(ctx context.Context, conn *grpc.ClientConn, endpoint string) error {
	printer.Debugf("Validating the CRI v1 API runtime version")
	r.runtimeClient = runtimeapi.NewRuntimeServiceClient(conn)

	if _, err := r.runtimeClient.Version(ctx, &runtimeapi.VersionRequest{}); err != nil {
		return errors.Wrapf(err, "validate CRI v1 runtime API for endpoint %q failed", endpoint)
	}

	printer.Debugf("Validated CRI v1 runtime API")
	return nil
}
