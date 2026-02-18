package rest

import (
	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/api_schema"
)

type PostmanMetaData struct {
	CollectionID string `json:"collection_id"`
	Environment  string `json:"environment,omitempty"`
}

// TODO: shouldn't this be in akita-cli/api_schema?
type Service struct {
	ID              akid.ServiceID  `json:"id"`
	Name            string          `json:"name"`
	PostmanMetaData PostmanMetaData `json:"postman_meta_data"`
}

type User = api_schema.UserResponse

type CreateServiceResponse struct {
	RequestID  akid.RequestID `json:"request_id"`
	ResourceID akid.ServiceID `json:"resource_id"`
}

type ErrorResponse struct {
	RequestID  akid.RequestID `json:"request_id"`
	Message    string         `json:"message"`
	ResourceID string         `json:"resource_id"`
}

type InsightsService struct {
	ID   akid.ServiceID `json:"service_id"`
	Name string         `json:"service_name"`
}

type PostmanUser struct {
	ID     int    `json:"id"`
	Email  string `json:"email"`
	TeamID int    `json:"team_id"`
}

// CreateApplicationRequest represents the request body for creating an application
type CreateApplicationRequest struct {
	SystemEnv string `json:"system_env"`
}

// CreateApplicationResponse represents the response for application creation
type CreateApplicationResponse struct {
	ApplicationID string         `json:"application_id"`
	ServiceID     akid.ServiceID `json:"service_id"`
	ServiceName   string         `json:"service_name"`
}

// DiscoverServiceRequest is sent by the agent to discover a service
// via K8s autodiscovery. Used by both sidecar and daemonset modes.
type DiscoverServiceRequest struct {
	ServiceName   string            `json:"service_name"`
	ClusterName   string            `json:"cluster_name"`
	Namespace     string            `json:"namespace"`
	WorkloadName  string            `json:"workload_name"`
	WorkloadType  string            `json:"workload_type"`
	Labels        map[string]string `json:"labels,omitempty"`
	DiscoveryMode string            `json:"discovery_mode"`
}

// DiscoverServiceResponse is returned after discovering a service.
type DiscoverServiceResponse struct {
	ServiceID string `json:"service_id"`
	Status    string `json:"status"`
	IsNew     bool   `json:"is_new"`
}
