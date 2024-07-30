package kube

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/postmanlabs/postman-insights-agent/cmd/internal/cmderr"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
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
	// Store it in an array since the fragment will be added to a list of containers
	containerArray := []v1.Container{container}

	containerYamlBytes, err := yaml.Marshal(containerArray)
	if err != nil {
		return err
	}

	// Trim off any extraneous newlines.
	containerYamlBytes = bytes.Trim(containerYamlBytes, "\n")

	// Indent four levels to line up with the expected indent level of the other container definitions
	prefix := "        "
	containerYaml := prefix + strings.ReplaceAll(string(containerYamlBytes), "\n", "\n"+prefix)

	fmt.Printf("\n%s\n", containerYaml)
	return nil
}

func init() {
	Cmd.AddCommand(printHelmChartSnippetCmd)
}
