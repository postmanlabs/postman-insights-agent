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
