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

func init() {
	// TODO: Move --project down to individual subcommands (inject, helm-fragment,
	// tf-fragment) that actually use it. Keeping it here as a persistent flag
	// forces kube run to hide it and prevents Cobra's MarkFlagsMutuallyExclusive
	// from working across parent/child flag boundaries.
	Cmd.PersistentFlags().StringVar(
		&insightsProjectID,
		"project",
		"",
		"Your Postman Insights project ID.")
}
