package kube

import (
	"github.com/spf13/cobra"
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
)

// addOnboardingModeFlags registers the onboarding-mode flags as local flags
// on cmd and sets up mutual-exclusivity / required-together constraints.
func addOnboardingModeFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&insightsProjectID, "project", "", "Your Postman Insights project ID.")
	cmd.Flags().StringVar(&onboardWorkspaceID, "workspace-id", "", "Your Postman workspace ID. Used to automatically create/link with an API Catalog application.")
	cmd.Flags().StringVar(&onboardSystemEnv, "system-env", "", "The system environment UUID. Required when --workspace-id is specified.")
	cmd.Flags().BoolVar(&onboardDiscoveryMode, "discovery-mode", false, "Enable auto-discovery without requiring a project ID.")
	cmd.Flags().StringVar(&onboardServiceName, "service-name", "", "Override the auto-derived service name.")
	cmd.Flags().StringVar(&onboardClusterName, "cluster-name", "", "Kubernetes cluster name (required for --discovery-mode). Used to uniquely identify the cluster and prevent data mixing across environments.")
	cmd.MarkFlagsMutuallyExclusive("workspace-id", "discovery-mode", "project")
	cmd.MarkFlagsRequiredTogether("workspace-id", "system-env")
	cmd.MarkFlagsRequiredTogether("discovery-mode", "cluster-name")
}
