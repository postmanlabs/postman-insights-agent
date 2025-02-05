package kube

import (
	"os"

	"github.com/postmanlabs/postman-insights-agent/cmd/internal/cmderr"
	"github.com/postmanlabs/postman-insights-agent/cmd/internal/kube/daemonset"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the Postman Insights Agent in your Kubernetes cluster as a daemon-set",
	Long:  "Run the Postman Insights Agent in your Kubernetes cluster as a daemon-set to collect and send data to Postman Insights",
	RunE: func(_ *cobra.Command, args []string) error {
		clusterName := os.Getenv("POSTMAN_CLUSTER_NAME")
		if clusterName == "" {
			clusterName = "default" // Do we need a default value? Is this required env var?
		}

		if err := daemonset.StartDaemonset(daemonset.Args{ClusterName: clusterName}); err != nil {
			return cmderr.AkitaErr{Err: err}
		}
		return nil
	},
}

func init() {
	// TODO(K8s-MNS): Hide/remove parent flags
	Cmd.AddCommand(runCmd)
}
