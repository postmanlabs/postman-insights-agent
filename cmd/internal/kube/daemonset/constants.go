package daemonset

import "time"

const (
	// Pod environment variables
	POSTMAN_INSIGHTS_PROJECT_ID         = "POSTMAN_INSIGHTS_PROJECT_ID"
	POSTMAN_INSIGHTS_API_KEY            = "POSTMAN_INSIGHTS_API_KEY"
	POSTMAN_INSIGHTS_DISABLE_REPRO_MODE = "POSTMAN_INSIGHTS_DISABLE_REPRO_MODE"
	POSTMAN_INSIGHTS_DROP_NGINX_TRAFFIC = "POSTMAN_INSIGHTS_DROP_NGINX_TRAFFIC"
	POSTMAN_INSIGHTS_AGENT_RATE_LIMIT   = "POSTMAN_INSIGHTS_AGENT_RATE_LIMIT"

	// Daemonset environment variables
	POSTMAN_INSIGHTS_ENV                = "POSTMAN_ENV" // This is same as root POSTMAN_ENV
	POSTMAN_INSIGHTS_VERIFICATION_TOKEN = "POSTMAN_INSIGHTS_VERIFICATION_TOKEN"
	POSTMAN_INSIGHTS_CLUSTER_NAME       = "POSTMAN_INSIGHTS_CLUSTER_NAME"

	// Workers intervals
	DefaultTelemetryInterval      = 5 * time.Minute
	DefaultPodHealthCheckInterval = 5 * time.Minute
)
