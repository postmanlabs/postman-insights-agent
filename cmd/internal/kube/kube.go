package kube

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/postmanlabs/postman-insights-agent/cmd/internal/cmderr"
	"github.com/postmanlabs/postman-insights-agent/ebpf"
)

var Cmd = &cobra.Command{
	Use:   "kube",
	Short: "Install the Postman Insights Agent in your Kubernetes cluster",
	Aliases: []string{
		"k8s",
		"kubernetes",
	},
}

// Shared onboarding-mode flags used by inject, helm-fragment, and tf-fragment.
// Only one subcommand runs at a time, so a single set of variables is safe.
var (
	insightsProjectID    string
	onboardDiscoveryMode bool
	onboardServiceName   string
	onboardClusterName   string
	onboardWorkspaceID   string
	onboardSystemEnv     string

	// HTTPS-via-eBPF onboarding flag. When set, the generated container spec
	// requests CAP_BPF + CAP_PERFMON, mounts /sys/kernel/debug + /sys/fs/bpf
	// + /host/proc, and the agent runs with --enable-https-capture. Customers
	// who don't need HTTPS keep the minimal NET_RAW posture.
	onboardEnableHTTPSCapture bool
	// onboardHTTPSLibraries is --https-libraries for the generated agent.
	onboardHTTPSLibraries []string
)

// httpsLibrariesFlag is the name of the onboarding commands' --https-libraries.
const httpsLibrariesFlag = "https-libraries"

// addOnboardingModeFlags registers the onboarding-mode flags as local flags
// on cmd and sets up mutual-exclusivity / required-together constraints.
func addOnboardingModeFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&insightsProjectID, "project", "", "Your Postman Insights project ID.")
	cmd.Flags().StringVar(&onboardWorkspaceID, "workspace-id", "", "Your Postman workspace ID. Used to automatically create/link with an API Catalog application.")
	cmd.Flags().StringVar(&onboardSystemEnv, "system-env", "", "The system environment UUID. Required when --workspace-id is specified.")
	cmd.Flags().BoolVar(&onboardDiscoveryMode, "discovery-mode", false, "Enable auto-discovery without requiring a project ID.")
	cmd.Flags().StringVar(&onboardServiceName, "service-name", "", "Override the auto-derived service name.")
	cmd.Flags().StringVar(&onboardClusterName, "cluster-name", "", "Kubernetes cluster name (required for --discovery-mode). Used to uniquely identify the cluster and prevent data mixing across environments.")
	cmd.Flags().BoolVar(&onboardEnableHTTPSCapture, "enable-https-capture", false, "Generate a container spec that enables HTTPS traffic capture via eBPF. Adds CAP_BPF + CAP_PERFMON, hostPID requirement, and required hostPath volume mounts.")
	cmd.Flags().StringSliceVar(&onboardHTTPSLibraries, httpsLibrariesFlag, nil, "With --enable-https-capture, the TLS libraries the agent captures HTTPS traffic from: openssl, java (preview; the JVMs need -javaagent, since a sidecar does not load the agent into running JVMs, and java adds CAP_SYS_PTRACE, to switch on the agents of JVMs running as another user). Default: the agent's default, openssl.")
	cmd.MarkFlagsMutuallyExclusive("workspace-id", "discovery-mode", "project")
	cmd.MarkFlagsRequiredTogether("workspace-id", "system-env")
	cmd.MarkFlagsRequiredTogether("discovery-mode", "cluster-name")
}

// onboardHTTPSLibrariesArg checks cmd's --https-libraries and returns the
// value to pass to the generated agent, or "" to keep the agent's default
// when the flag is not given. A flag given an empty value names no library,
// which is an error, rather than the default.
func onboardHTTPSLibrariesArg(cmd *cobra.Command) (string, error) {
	if !cmd.Flags().Changed(httpsLibrariesFlag) {
		return "", nil
	}
	if !onboardEnableHTTPSCapture {
		return "", cmderr.AkitaErr{Err: errors.New("--https-libraries requires --enable-https-capture")}
	}
	libs, unknown := ebpf.ParseLibraries(onboardHTTPSLibraries)
	if len(unknown) > 0 {
		return "", cmderr.AkitaErr{Err: errors.Errorf("--https-libraries: unknown %s (supported: %s)",
			strings.Join(unknown, ", "), strings.Join(ebpf.SupportedLibraries, ", "))}
	}
	if libs.None() {
		return "", cmderr.AkitaErr{Err: errors.New("--https-libraries names no library")}
	}
	return libs.String(), nil
}
