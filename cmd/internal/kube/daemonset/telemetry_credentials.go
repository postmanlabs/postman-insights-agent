package daemonset

import (
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/rest"
)

// telemetryAuth is how daemonset telemetry requests are authenticated.
// Enabled is false when neither a verification token nor a DaemonSet API key is set.
type telemetryAuth struct {
	handler   rest.AuthHandler
	enabled   bool
	viaAPIKey bool
}

// selectTelemetryAuth prefers the team verification token.
// When that is unset, it falls back to the DaemonSet Postman API key.
// When neither is set, telemetry must not be sent.
func selectTelemetryAuth(verificationToken, apiKey, postmanEnv string) telemetryAuth {
	if verificationToken != "" {
		return telemetryAuth{
			handler: rest.DaemonsetAuthHandler(verificationToken),
			enabled: true,
		}
	}
	if apiKey != "" {
		return telemetryAuth{
			handler:   rest.ApiDumpDaemonsetAuthHandler(apiKey, postmanEnv),
			enabled:   true,
			viaAPIKey: true,
		}
	}
	return telemetryAuth{}
}

// resolveTelemetryClusterName returns the cluster name used in telemetry.
// Discovery mode still requires an explicit name, because that name is part of
// the discovered service slug.
func resolveTelemetryClusterName(clusterName string, discoveryMode bool) (string, error) {
	if clusterName != "" {
		return clusterName, nil
	}
	if discoveryMode {
		return "", errors.New(
			"discovery mode requires a cluster name: set POSTMAN_INSIGHTS_CLUSTER_NAME env var",
		)
	}
	return DefaultTelemetryClusterName, nil
}
