package daemonset

import "time"

const (
	// Pod environment variables
	POSTMAN_INSIGHTS_PROJECT_ID = "POSTMAN_INSIGHTS_PROJECT_ID"
	POSTMAN_INSIGHTS_API_KEY    = "POSTMAN_INSIGHTS_API_KEY"

	// Daemonset environment variables
	POSTMAN_INSIGHTS_ENV                = "POSTMAN_INSIGHTS_ENV"
	POSTMAN_INSIGHTS_VERIFICATION_TOKEN = "POSTMAN_INSIGHTS_VERIFICATION_TOKEN"
	POSTMAN_INSIGHTS_CLUSTER_NAME       = "POSTMAN_INSIGHTS_CLUSTER_NAME"
	POSTMAN_INSIGHTS_REPRO_MODE_ENABLED = "POSTMAN_INSIGHTS_REPRO_MODE_ENABLED"

	// Workers intervals
	DefaultTelemetryInterval      = 5 * time.Minute
	DefaultPodHealthCheckInterval = 5 * time.Minute
)
