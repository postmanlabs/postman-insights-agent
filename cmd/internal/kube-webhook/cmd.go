// SPDX-License-Identifier: Apache-2.0

// Package kubewebhook is the Phase 5c.3 mutating admission webhook that
// auto-injects the Java agent into pods in opted-in namespaces.
//
// Architecture
// ============
//
//   1. A `MutatingWebhookConfiguration` (deployed in 5c.3b) tells the K8s
//      API server: "for pod CREATE in namespaces matching label
//      `postman.dev/insights=enabled`, call POST https://<webhook>/mutate".
//      `namespaceSelector` filters BEFORE we see the request, so this
//      webhook never has to query the API server for namespace labels.
//
//   2. This webhook receives `admission/v1.AdmissionReview` requests,
//      decodes the pod, checks whether it looks Java (image regex / env /
//      command), and if so returns a JSON Patch (RFC 6902) that:
//        a. Adds an `emptyDir` volume `postman-agent`.
//        b. Adds an init container that copies the agent JAR + native lib
//           from `--init-image` into `/postman/`.
//        c. For every Java-detected container:
//           - Adds a `volumeMount` at `/postman/`.
//           - Adds `JAVA_TOOL_OPTIONS=-javaagent:/postman/postman-java-agent.jar`
//             (appending to any existing value, NEVER replacing).
//
//   3. The K8s API server applies the patch before the pod is admitted.
//      `failurePolicy: Ignore` in the WebhookConfiguration is the safety net:
//      if this webhook is unreachable or returns an error, the API server
//      admits the pod un-mutated. A bug here CANNOT break cluster pod
//      creation.
//
// 5c.3a delivers: this Go package + unit tests + a hidden CLI subcommand.
// 5c.3b will deliver: YAML manifests, kind cluster e2e, rehearsed rollback.
// 5c.3c will deliver: Helm chart + production docs.
package kubewebhook

import (
	"github.com/spf13/cobra"
)

// Cmd is the hidden Cobra subcommand exposed by the agent CLI.
var Cmd = &cobra.Command{
	Use:    "kube-webhook",
	Short:  "Phase 5c.3 mutating admission webhook that auto-injects the Java agent",
	Long:   "Phase 5c.3 K8s mutating admission webhook. Runs as a separate Deployment in the cluster (not the DaemonSet). NOT for direct production use yet — see docs/phases/phase-5-plan.md §5c.3.",
	Hidden: true,
	RunE:   runE,
}
