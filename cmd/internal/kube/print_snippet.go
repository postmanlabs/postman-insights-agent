package kube

import (
	"github.com/postmanlabs/postman-insights-agent/cfg"
	"github.com/postmanlabs/postman-insights-agent/cmd/internal/cmderr"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/spf13/cobra"
	"github.com/zclconf/go-cty/cty"
	"sigs.k8s.io/yaml"

	"github.com/hashicorp/hcl/v2/hclwrite"
)

var printHelmChartSnippetCmd = &cobra.Command{
	Use:   "helm-sidecar-snippet",
	Short: "Print a Helm chart container definition for adding the Postman Insights Agent to existing k8s deployment.",
	Long:  "Print a container definition that can be inserted into a Helm Chart template to add the Postman Insights Agent as a sidecar container.",
	RunE:  printHelmChartSnippet,
}

var printTerraformChartSnippetCmd = &cobra.Command{
	Use:   "tf-sidecar-snippet",
	Short: "Print an Terraform code snippet for adding the Postman Insights Agent to an existing k8s deployment.",
	Long:  "Print a Terraform code snippet that can be inserted into a Terraform kubernetes_deployment resource spec to add the Postman Insights Agent as a sidecar container.",
	RunE:  printTerraformChartSnippet,
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
	printer.Infof("\n%s\n", string(containerYaml))
	return nil
}

func printTerraformChartSnippet(cmd *cobra.Command, args []string) error {
	err := cmderr.CheckAPIKeyAndInsightsProjectID(insightsProjectID)
	if err != nil {
		return err
	}

	// Create the Postman Insights Agent sidecar container
	a := createTerraformContainer(insightsProjectID)

	// Print the snippet
	printer.Infof("\n%s\n", string(a.Bytes()))
	return nil
}

func createTerraformContainer(insightsProjectID string) *hclwrite.File {
	hclConfig := hclwrite.NewEmptyFile()
	rootBody := hclConfig.Body()
	containerBlock := rootBody.AppendNewBlock("container", []string{})
	containerBody := containerBlock.Body()

	containerBody.SetAttributeValue("name", cty.StringVal("postman-insights-agent"))
	containerBody.SetAttributeValue("image", cty.StringVal(akitaImage))

	containerBody.AppendNewBlock("lifecycle", []string{}).
		Body().AppendNewBlock("pre_stop", []string{}).
		Body().AppendNewBlock("exec", []string{}).
		Body().SetAttributeValue("command", cty.ListVal([]cty.Value{
		cty.StringVal("/bin/sh"),
		cty.StringVal("-c"),
		cty.StringVal("POSTMAN_INSIGHTS_AGENT_PID=$(pgrep postman-insights-agent) && kill -2 $POSTMAN_INSIGHTS_AGENT_PID && tail -f /proc/$POSTMAN_INSIGHTS_AGENT_PID/fd/1"),
	}))

	containerBody.AppendNewBlock("security_context", []string{}).
		Body().AppendNewBlock("capabilities", []string{}).
		Body().SetAttributeValue("add", cty.ListVal([]cty.Value{
		cty.StringVal("NET_RAW"),
	}))

	// Add the args to the container
	args := cty.ListVal([]cty.Value{
		cty.StringVal("apidump"),
		cty.StringVal("--project"),
		cty.StringVal(insightsProjectID),
	})
	// If a nondefault --domain flag was used, specify it for the container as well.
	if rest.Domain != rest.DefaultDomain() {
		args.Add(cty.StringVal("--domain"))
		args.Add(cty.StringVal(rest.Domain))
	}
	containerBody.SetAttributeValue("args", args)

	// Add the environment variables to the container
	pmKey, pmEnv := cfg.GetPostmanAPIKeyAndEnvironment()
	APIKeyEnvBlockBody := containerBody.AppendNewBlock("env", []string{}).Body()
	APIKeyEnvBlockBody.SetAttributeValue("name", cty.StringVal("POSTMAN_API_KEY"))
	APIKeyEnvBlockBody.SetAttributeValue("value", cty.StringVal(pmKey))

	if pmEnv != "" {
		PostmanEnvBlockBody := containerBody.AppendNewBlock("env", []string{}).Body()
		PostmanEnvBlockBody.SetAttributeValue("name", cty.StringVal("POSTMAN_ENV"))
		PostmanEnvBlockBody.SetAttributeValue("value", cty.StringVal(pmEnv))
	}

	return hclConfig
}
