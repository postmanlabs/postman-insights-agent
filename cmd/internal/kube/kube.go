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

	// `kube inject` command level flags
	injectCmd.Flags().StringVarP(
		&injectFileNameFlag,
		"file",
		"f",
		"",
		"Path to the Kubernetes YAML file to be injected. This should contain a Deployment object.",
	)
	_ = injectCmd.MarkFlagRequired("file")

	injectCmd.Flags().StringVarP(
		&injectOutputFlag,
		"output",
		"o",
		"",
		"Path to the output file. If not specified, the output will be printed to stdout.",
	)

	injectCmd.Flags().StringVarP(
		&secretInjectFlag,
		"secret",
		"s",
		"false",
		`Whether to generate a Kubernetes Secret. If set to "true", the secret will be added to the modified Kubernetes YAML file. Specify a path to write the secret to a separate file; if this is done, an output file must also be specified with --output.`,
	)
	// Default value is "true" when the flag is given without an argument.
	injectCmd.Flags().Lookup("secret").NoOptDefVal = "true"

	Cmd.AddCommand(injectCmd)
	Cmd.AddCommand(printHelmChartSnippetCmd)
}
