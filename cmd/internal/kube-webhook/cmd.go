// Package kubewebhook implements the mutating admission webhook that
// auto-injects the Postman Java agent into pods in opted-in namespaces.
//
// Architecture
// ============
//
//  1. A MutatingWebhookConfiguration tells the K8s API server: "for pod CREATE
//     in namespaces matching label `postman.com/insights=enabled`, call
//     POST https://<webhook>/mutate". namespaceSelector filters BEFORE we see
//     the request, so this webhook never has to query the API server for
//     namespace labels.
//
//  2. This webhook receives admission/v1.AdmissionReview requests, decodes the
//     pod, checks whether it looks Java (image regex / env / command), and if
//     so returns a JSON Patch (RFC 6902) that:
//       a. Adds an emptyDir volume `postman-insights-agent`.
//       b. Adds an init container that copies the agent JAR from --init-image
//          into /postman/.
//       c. For every Java-detected container:
//          - Adds a volumeMount at /postman/.
//          - Adds JAVA_TOOL_OPTIONS=-javaagent:/postman/postman-java-agent.jar
//            (appending to any existing value, NEVER replacing).
//
//  3. The K8s API server applies the patch before the pod is admitted.
//     failurePolicy: Ignore in the MutatingWebhookConfiguration is the safety
//     net: if this webhook is unreachable or returns an error, the API server
//     admits the pod un-mutated. A bug here CANNOT break cluster pod creation.
//
// Deployment
// ==========
// This command runs inside the cluster as a separate Deployment (not the
// DaemonSet). It is invoked by the Helm chart as:
//
//	postman-insights-agent kube webhook --addr=:<port> --tls-cert=... --tls-key=... --init-image=...
//
// See charts/postman-insights-webhook/ for the chart.
package kubewebhook

import (
	"github.com/spf13/cobra"
)

// Cmd is the Cobra subcommand registered under `kube` (`kube webhook`).
var Cmd = &cobra.Command{
	Use:   "webhook",
	Short: "Run the mutating admission webhook that auto-injects the Postman Java agent",
	Long: `Starts the HTTPS server that the K8s API server calls for every pod CREATE in
opted-in namespaces (label postman.com/insights=enabled). The webhook inspects
each pod and injects the Postman Java agent via an init container and
JAVA_TOOL_OPTIONS if the pod looks like a Java workload.

This command is intended to run inside the cluster as a Deployment, not on a
developer's machine. Use the Helm chart in charts/postman-insights-webhook/
to deploy it.`,
	RunE: runE,
}
