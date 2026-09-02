package rest

import (
	"time"

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
	ServiceID        string     `json:"service_id"`
	Status           string     `json:"status"`
	IsNew            bool       `json:"is_new"`
	TrafficExpiresAt *time.Time `json:"traffic_expires_at,omitempty"`
}

// TelemetryType distinguishes the kinds of message that share the daemonset
// telemetry endpoint. Without it, a consumer cannot tell a point-in-time
// coverage snapshot from an interval counter row, because both carry an event
// name.
type TelemetryType string

const (
	TelemetryTypeSnapshot TelemetryType = "snapshot"
	TelemetryTypeEvents   TelemetryType = "events"
)

// CounterType declares how a numeric telemetry value must be read. Required on
// every counter: a consumer that guesses will subtract unrelated snapshots and
// treat the result as a funnel count.
type CounterType string

const (
	// CounterTypeIntervalDelta is activity within [WindowStart, WindowEnd).
	CounterTypeIntervalDelta CounterType = "interval_delta"
)

// AgentState is a self-reported summary of whether the DaemonSet agent
// process is operating normally. It is distinct from heartbeat staleness,
// which a consumer derives from heartbeat age rather than from this field.
type AgentState string

const (
	AgentStateHealthy  AgentState = "healthy"
	AgentStateDegraded AgentState = "degraded"
)

// DaemonsetTelemetryRequest is the local-first coverage payload. Targets is
// intentionally opaque here so the REST package does not depend on DaemonSet
// implementation types.
type DaemonsetTelemetryRequest struct {
	Type              TelemetryType `json:"type,omitempty"`
	Event             string        `json:"event,omitempty"`
	AgentID           string        `json:"agent_id,omitempty"`
	Sequence          uint64        `json:"sequence,omitempty"`
	SchemaVersion     string        `json:"schema_version,omitempty"`
	KubernetesCluster string        `json:"kubernetes_cluster,omitempty"`

	// Agent-scope metadata. Present on agent_started, agent_heartbeat, and
	// agent_stopped.
	AgentVersion    string     `json:"agent_version,omitempty"`
	GitVersion      string     `json:"git_version,omitempty"`
	AgentState      AgentState `json:"agent_state,omitempty"`
	AgentStateSince *time.Time `json:"agent_state_since,omitempty"`

	// FailureCategory is a normalized, bounded category for a terminal
	// agent-scope failure. Present only on agent_failed.
	FailureCategory string `json:"failure_category,omitempty"`

	// Snapshot fields.
	Targets          any            `json:"targets,omitempty"`
	TruncatedTargets uint64         `json:"truncated_targets,omitempty"`
	StageCounts      map[string]int `json:"stage_counts,omitempty"`

	// Counter fields.
	TargetID    string      `json:"target_id,omitempty"`
	Count       uint64      `json:"count,omitempty"`
	CounterType CounterType `json:"counter_type,omitempty"`
	WindowStart *time.Time  `json:"window_start,omitempty"`
	WindowEnd   *time.Time  `json:"window_end,omitempty"`

	// ServiceID identifies the Insights project a counter's TargetID
	// currently resolves to. Target-scoped like TargetID itself, not
	// agent-scoped: a single DaemonSet agent can watch pods belonging to
	// different projects, so there is no one value that applies to the whole
	// request. Empty on rows without a TargetID, and can legitimately be
	// empty even on a counter row if that target hasn't resolved yet.
	ServiceID string `json:"service_id,omitempty"`

	// UserID and TeamID are the agent-reported Postman identity, and the only
	// tenancy the backend records -- it stores what we send here rather than
	// deriving a team from the verification token. Getting them wrong or
	// leaving them empty means the row cannot be attributed to a customer, so
	// populate them wherever an identity is known.
	//
	// Scope follows the row. On the top-level request they are agent-scope,
	// resolved once at startup from the DaemonSet's own API key. On an Events
	// element they are target-scope, resolved from that pod's own API key --
	// which can belong to a different team than the one that installed the
	// agent.
	//
	// Both can legitimately be empty: a target that hasn't reached
	// SetTrackingUser, or an agent with no DaemonSet-level API key (only
	// discovery mode requires one).
	UserID string `json:"user_id,omitempty"`
	TeamID string `json:"team_id,omitempty"`

	// Events batches additional, independent events/counters into this same
	// POST. Every heartbeat interval used to flush its counter map as
	// one HTTP request per (event, target) pair -- 40 pods x ~6 events could
	// mean ~240 requests per interval. Events carries exactly those rows
	// inline instead: each element is a self-contained
	// DaemonsetTelemetryRequest (its own Type/Event/TargetID/Count/etc.), and
	// the outer request's identity fields (AgentID, KubernetesCluster,
	// Sequence, ...) apply to the whole batch, not repeated per element. A
	// consumer that has never seen this field simply ignores it and still
	// gets the outer request's own event -- additive, not breaking.
	Events []DaemonsetTelemetryRequest `json:"events,omitempty"`
}
