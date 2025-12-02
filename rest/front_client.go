package rest

import (
	"context"
	"path"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/api_schema"
	"github.com/akitasoftware/akita-libs/daemon"
)

type frontClientImpl struct {
	*BaseClient
}

var _ FrontClient = (*frontClientImpl)(nil)

func NewFrontClient(host string, cli akid.ClientID, authHandler AuthHandler, apiErrorHandler APIErrorHandler) *frontClientImpl {
	return &frontClientImpl{
		BaseClient: NewBaseClient(host, cli, authHandler, apiErrorHandler),
	}
}

// Deprecated: Replaced with GetService(), will be removed in the future.
func (c *frontClientImpl) GetServices(ctx context.Context) ([]Service, error) {
	resp := []Service{}
	if err := c.Get(ctx, "/v1/services", &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *frontClientImpl) GetService(ctx context.Context, serviceID akid.ServiceID) (InsightsService, error) {
	var resp InsightsService
	path := path.Join("/v2/agent/services", akid.String(serviceID))
	if err := c.Get(ctx, path, &resp); err != nil {
		return InsightsService{}, err
	}
	return resp, nil
}

func (c *frontClientImpl) CreateInsightsService(ctx context.Context, workspaceID string, serviceName string, serviceEnvironment string) (CreateInsightsServiceResponse, error) {
	var resp CreateInsightsServiceResponse
	p := path.Join("v2/agent/workspaces", workspaceID, "services")

	req := map[string]interface{}{}
	if serviceName != "" {
		req["service_name"] = serviceName
	}
	if serviceEnvironment != "" {
		req["service_environment"] = serviceEnvironment
	}

	err := c.Post(ctx, p, req, &resp)
	return resp, err
}

func (c *frontClientImpl) GetUser(ctx context.Context) (PostmanUser, error) {
	resp := PostmanUser{}
	err := c.Get(ctx, "/v2/agent/user", &resp)
	return resp, err
}

// Deprecated: Used in daemon command which is deprecated.
func (c *frontClientImpl) DaemonHeartbeat(ctx context.Context, daemonName string) error {
	body := struct {
		DaemonName string `json:"daemon_name"`
	}{
		DaemonName: daemonName,
	}
	resp := struct{}{}
	return c.Post(ctx, "/v1/daemon/heartbeat", body, &resp)
}

// Deprecated: Used in daemon command which is deprecated.
func (c *frontClientImpl) LongPollActiveTracesForService(ctx context.Context, daemonName string, serviceID akid.ServiceID, activeTraces []akid.LearnSessionID) (daemon.ActiveTraceDiff, error) {
	body := struct {
		DaemonName     string                `json:"daemon_name"`
		ActiveTraceIDs []akid.LearnSessionID `json:"active_trace_ids"`
	}{
		DaemonName:     daemonName,
		ActiveTraceIDs: activeTraces,
	}
	var resp daemon.ActiveTraceDiff
	path := path.Join("/v1/services", akid.String(serviceID), "daemon")
	err := c.Post(ctx, path, body, &resp)
	return resp, err
}

// Create a mirror service in the user's organization. The environment is implicit based
// on credentials.
func (c *frontClientImpl) CreateService(ctx context.Context, serviceName string, collectionId string) (CreateServiceResponse, error) {
	resp := CreateServiceResponse{}
	body := struct {
		Name            string          `json:"name"`
		PostmanMetaData PostmanMetaData `json:"postman_meta_data"`
	}{
		Name: serviceName,
		PostmanMetaData: PostmanMetaData{
			CollectionID: collectionId,
		},
	}

	err := c.Post(ctx, "/v1/services", body, &resp)

	return resp, err
}

func (c *frontClientImpl) PostDaemonsetAgentTelemetry(ctx context.Context, clusterName string) error {
	req := api_schema.PostDaemonsetTelemetryRequest{
		KubernetesCluster: clusterName,
	}
	path := "/v2/agent/daemonset/telemetry"
	var resp struct{}
	return c.Post(ctx, path, req, &resp)
}
