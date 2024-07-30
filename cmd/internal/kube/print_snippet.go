package kube

import (
	"fmt"

	"github.com/postmanlabs/postman-insights-agent/cmd/internal/cmderr"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

var printHelmChartSnippetCmd = &cobra.Command{
	Use:   "helm-snippet",
	Short: "Print a Helm chart container definition for adding the Postman Insights Agent to existing k8s deployment.",
	Long:  "Print a container definition that can be inserted into a Helm Chart template to add the Postman Insights Agent as a sidecar container.",
	RunE:  printHelmChartSnippet,
}

func printHelmChartSnippet(cmd *cobra.Command, args []string) error {
	err := cmderr.CheckAPIKeyAndInsightsProjectID(insightsProjectID)
	if err != nil {
		return err
	}

	// Create the Postman Insights Agent sidecar container
	container := createPostmanSidecar(insightsProjectID, false)

	// Print the snippet
	containerYaml, err := yaml.Marshal(container)
	if err != nil {
		return err
	}
	fmt.Printf("\n%s\n", string(containerYaml))
	return nil
}

func init() {
	Cmd.AddCommand(printHelmChartSnippetCmd)
}
