package daemonset

type daemonsetEnvVars string

const (
	POSTMAN_INSIGHTS_PROJECT_ID daemonsetEnvVars = "POSTMAN_INSIGHTS_PROJECT_ID"
	POSTMAN_INSIGHTS_API_KEY    daemonsetEnvVars = "POSTMAN_INSIGHTS_API_KEY"
	POSTMAN_INSIGHTS_ENV        daemonsetEnvVars = "POSTMAN_INSIGHTS_ENV"
)
