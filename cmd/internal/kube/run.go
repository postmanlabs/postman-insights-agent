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

	// HTTPS capture via eBPF uprobes on libssl.
	enableHTTPSCapture   bool
	httpsRateCapPerSec   uint32
	httpsBodySizeCap     uint32
	httpsCBPFExcludePort uint16
	httpsNoThermostat    bool
)

func StartDaemonsetAndHibernateOnError(_ *cobra.Command, args []string) error {
	err := daemonset.StartDaemonset(daemonset.DaemonsetArgs{
		ReproMode:            reproMode,
		RateLimit:            rateLimit,
		DiscoveryMode:        discoveryMode,
		IncludeNamespaces:    includeNamespaces,
		ExcludeNamespaces:    excludeNamespaces,
		IncludeLabels:        includeLabels,
		ExcludeLabels:        excludeLabels,
		EnableHTTPSCapture:   enableHTTPSCapture,
		HTTPSRateCapPerSec:   httpsRateCapPerSec,
		HTTPSBodySizeCap:     httpsBodySizeCap,
		HTTPSCBPFExcludePort: httpsCBPFExcludePort,
		HTTPSNoThermostat:    httpsNoThermostat,
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
		"Enable auto-discovery of K8s services without requiring a project ID. Requires POSTMAN_INSIGHTS_CLUSTER_NAME to be set.",
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
	// HTTPS capture flags — require the agent pod to have hostPID:true,
	// CAP_BPF + CAP_PERFMON, and /host/proc + /sys/fs/bpf volume mounts.
	// See docs/https-capture-design.md §8.1 for the required pod spec.
	runCmd.PersistentFlags().BoolVar(
		&enableHTTPSCapture,
		"enable-https-capture",
		false,
		"Capture HTTPS traffic using eBPF uprobes on libssl (requires hostPID:true, CAP_BPF + CAP_PERFMON).",
	)
	runCmd.PersistentFlags().Uint32Var(
		&httpsRateCapPerSec,
		"https-rate-cap-per-sec",
		0,
		"Per-PID eBPF event rate cap (events/sec). 0 = unlimited.",
	)
	runCmd.PersistentFlags().Uint32Var(
		&httpsBodySizeCap,
		"https-body-size-cap",
		0,
		"Maximum bytes captured per HTTPS payload (0 = default 4096).",
	)
	runCmd.PersistentFlags().BoolVar(
		&httpsNoThermostat,
		"no-thermostat",
		false,
		"Disable the CPU thermostat that lowers max-capture-bytes under load.",
	)
	runCmd.PersistentFlags().Uint16Var(
		&httpsCBPFExcludePort,
		"https-cbpf-exclude-port",
		443,
		"TCP port whose packets are removed from the cBPF filter when --enable-https-capture is set. "+
			"Avoids double-counting TLS handshake bytes already captured via eBPF. 0 disables exclusion.",
	)

	Cmd.AddCommand(runCmd)
}
