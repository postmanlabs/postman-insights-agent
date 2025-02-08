package kube

import (
	"os"

	"github.com/postmanlabs/postman-insights-agent/cmd/internal/cmderr"
	"github.com/postmanlabs/postman-insights-agent/cmd/internal/kube/daemonset"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the Postman Insights Agent in your Kubernetes cluster as a daemonSet",
	Long:  "Run the Postman Insights Agent in your Kubernetes cluster as a daemonSet to collect and send data to Postman Insights",
	RunE: func(_ *cobra.Command, args []string) error {
		clusterName := os.Getenv("POSTMAN_CLUSTER_NAME")
		if clusterName == "" {
			printer.Infof(
				"The cluster name is missing. Telemetry will not be sent from this agent, " +
					"it will not be tracked on our end, and it will not appear in the app's " +
					"list of clusters where the agent is running.",
			)
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
