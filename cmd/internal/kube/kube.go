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
	// `kube` command level flags
	Cmd.PersistentFlags().StringVar(
		&insightsProjectID,
		"project",
		"",
		"Your Postman Insights project ID.")
	_ = Cmd.MarkFlagRequired("project")
}
