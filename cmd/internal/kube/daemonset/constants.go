package daemonset

import "time"

type podEnvVars string

const (
	// Pod environment variables
	POSTMAN_INSIGHTS_PROJECT_ID podEnvVars = "POSTMAN_INSIGHTS_PROJECT_ID"
	POSTMAN_INSIGHTS_API_KEY    podEnvVars = "POSTMAN_INSIGHTS_API_KEY"
	POSTMAN_INSIGHTS_ENV        podEnvVars = "POSTMAN_INSIGHTS_ENV"

	// Workers intervals
	DefaultTelemetryInterval      = 5 * time.Minute
	DefaultPodHealthCheckInterval = 5 * time.Minute
)
