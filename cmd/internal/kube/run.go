package kube

import (
	"github.com/postmanlabs/postman-insights-agent/cmd/internal/kube/daemonset"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/spf13/cobra"
)

func StartDaemonsetAndHibernateOnError(_ *cobra.Command, args []string) error {
	err := daemonset.StartDaemonset()

	if err == nil {
		return nil
	}

	// Log the error and wait forever.
	printer.Stderr.Errorf("Error while starting the process: %v\n", err)
	printer.Stdout.Infof("This process will not exit, to avoid boot loops. Please correct the command line flags or environment and retry.\n")

	select {}
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the Postman Insights Agent in your Kubernetes cluster as a daemonSet. [Only supported for linux images]",
	Long:  "Run the Postman Insights Agent in your Kubernetes cluster as a daemonSet to collect and send data to Postman Insights. [Only supported for linux images]",
	RunE:  StartDaemonsetAndHibernateOnError,
}

func init() {
	// TODO(K8s-MNS): Hide/remove parent flags
	Cmd.AddCommand(runCmd)
}
