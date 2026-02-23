package kube

import (
	"github.com/postmanlabs/postman-insights-agent/cmd/internal/kube/daemonset"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/spf13/cobra"
)

var (
	reproMode         bool
	rateLimit         float64
	discoveryMode     bool
	includeNamespaces []string
	excludeNamespaces []string
	includeLabels     map[string]string
	excludeLabels     map[string]string
)

func StartDaemonsetAndHibernateOnError(_ *cobra.Command, args []string) error {
	err := daemonset.StartDaemonset(daemonset.DaemonsetArgs{
		ReproMode:         reproMode,
		RateLimit:         rateLimit,
		DiscoveryMode:     discoveryMode,
		IncludeNamespaces: includeNamespaces,
		ExcludeNamespaces: excludeNamespaces,
		IncludeLabels:     includeLabels,
		ExcludeLabels:     excludeLabels,
	})
	if err == nil {
		return nil
	}

	// Log the error and wait forever.
	printer.Errorf("Error while starting the process: %v\n", err)
	printer.Infof("This process will not exit, to avoid boot loops. Please correct the command line flags or environment and retry.\n")

	select {}
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the Postman Insights Agent in your Kubernetes cluster as a daemonSet. [Only supported for linux images]",
	Long:  "Run the Postman Insights Agent in your Kubernetes cluster as a daemonSet to collect and send data to Postman Insights. [Only supported for linux images]",
	RunE:  StartDaemonsetAndHibernateOnError,
}

func init() {
	runCmd.PersistentFlags().Float64Var(
		&rateLimit,
		"rate-limit",
		0.0,
		"Number of requests per minute to capture",
	)
	runCmd.PersistentFlags().BoolVar(
		&reproMode,
		"repro-mode",
		false,
		"Enable Repro Mode to capture request and response payloads for debugging.",
	)

	// Discovery mode flags
	runCmd.PersistentFlags().BoolVar(
		&discoveryMode,
		"discovery-mode",
		false,
		"Enable auto-discovery of K8s services without requiring a project ID.",
	)
	runCmd.PersistentFlags().StringSliceVar(
		&includeNamespaces,
		"include-namespaces",
		nil,
		"Comma-separated list of namespaces to include (empty = all except excluded).",
	)
	runCmd.PersistentFlags().StringSliceVar(
		&excludeNamespaces,
		"exclude-namespaces",
		nil,
		"Comma-separated list of namespaces to exclude (added to defaults).",
	)
	runCmd.PersistentFlags().StringToStringVar(
		&includeLabels,
		"include-labels",
		nil,
		"Labels that pods must have to be captured (key=value pairs).",
	)
	runCmd.PersistentFlags().StringToStringVar(
		&excludeLabels,
		"exclude-labels",
		nil,
		"Labels that exclude pods from capture (key=value pairs).",
	)
	Cmd.AddCommand(runCmd)
}
