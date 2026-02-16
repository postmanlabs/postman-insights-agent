package daemonset

import "time"

const (
	// Pod environment variables
	POSTMAN_INSIGHTS_WORKSPACE_ID            = "POSTMAN_INSIGHTS_WORKSPACE_ID"
	POSTMAN_INSIGHTS_PROJECT_ID              = "POSTMAN_INSIGHTS_PROJECT_ID"
	POSTMAN_INSIGHTS_API_KEY                 = "POSTMAN_INSIGHTS_API_KEY"
	POSTMAN_INSIGHTS_DISABLE_REPRO_MODE      = "POSTMAN_INSIGHTS_DISABLE_REPRO_MODE"
	POSTMAN_INSIGHTS_DROP_NGINX_TRAFFIC      = "POSTMAN_INSIGHTS_DROP_NGINX_TRAFFIC"
	POSTMAN_INSIGHTS_AGENT_RATE_LIMIT        = "POSTMAN_INSIGHTS_AGENT_RATE_LIMIT"
	POSTMAN_INSIGHTS_ALWAYS_CAPTURE_PAYLOADS = "POSTMAN_INSIGHTS_ALWAYS_CAPTURE_PAYLOADS"
	POSTMAN_INSIGHTS_SYSTEM_ENV              = "POSTMAN_INSIGHTS_SYSTEM_ENV"
	POSTMAN_INSIGHTS_SERVICE_NAME            = "POSTMAN_INSIGHTS_SERVICE_NAME"

	// Daemonset environment variables
	POSTMAN_INSIGHTS_ENV                = "POSTMAN_ENV" // This is same as root POSTMAN_ENV
	POSTMAN_INSIGHTS_VERIFICATION_TOKEN = "POSTMAN_INSIGHTS_VERIFICATION_TOKEN"
	POSTMAN_INSIGHTS_CLUSTER_NAME       = "POSTMAN_INSIGHTS_CLUSTER_NAME"

	// Discovery mode environment variables
	POSTMAN_INSIGHTS_DISCOVERY_MODE     = "POSTMAN_INSIGHTS_DISCOVERY_MODE"
	POSTMAN_INSIGHTS_INCLUDE_NAMESPACES = "POSTMAN_INSIGHTS_INCLUDE_NAMESPACES"
	POSTMAN_INSIGHTS_EXCLUDE_NAMESPACES = "POSTMAN_INSIGHTS_EXCLUDE_NAMESPACES"
	POSTMAN_INSIGHTS_INCLUDE_LABELS     = "POSTMAN_INSIGHTS_INCLUDE_LABELS"
	POSTMAN_INSIGHTS_EXCLUDE_LABELS     = "POSTMAN_INSIGHTS_EXCLUDE_LABELS"
	POSTMAN_INSIGHTS_REQUIRE_OPT_IN     = "POSTMAN_INSIGHTS_REQUIRE_OPT_IN"

	// Annotations for pod opt-in/opt-out
	AnnotationOptIn  = "postman.com/insights-enabled"
	AnnotationOptOut = "postman.com/insights-disabled"

	// Workers intervals
	DefaultTelemetryInterval      = 5 * time.Minute
	DefaultPodHealthCheckInterval = 5 * time.Minute
)

// DefaultExcludedNamespaces are system and infrastructure namespaces that are
// excluded from discovery by default in daemonset mode.
var DefaultExcludedNamespaces = []string{
	"kube-system",
	"kube-public",
	"kube-node-lease",
	"istio-system",
	"linkerd",
	"ingress-nginx",
	"cert-manager",
	"monitoring",
	"logging",
	"flux-system",
	"argocd",
}
