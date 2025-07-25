package kube

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/postmanlabs/postman-insights-agent/cfg"
	"github.com/postmanlabs/postman-insights-agent/cmd/internal/apidump"
	"github.com/postmanlabs/postman-insights-agent/cmd/internal/cmderr"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/spf13/cobra"
	"github.com/zclconf/go-cty/cty"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

var (
	printHelmApidumpFlags *apidump.CommonApidumpFlags
	printTFApidumpFlags   *apidump.CommonApidumpFlags
)

var printHelmChartFragmentCmd = &cobra.Command{
	Use:              "helm-fragment",
	Short:            "Print a Helm chart container definition for adding the Postman Insights Agent to existing kubernetes deployment.",
	Long:             "Print a container definition that can be inserted into a Helm Chart template to add the Postman Insights Agent as a sidecar container.",
	RunE:             printHelmChartFragment,
	PersistentPreRun: kubeCommandPreRun,
}

var printTerraformFragmentCmd = &cobra.Command{
	Use:              "tf-fragment",
	Short:            "Print a Terraform (HCL) code fragment for adding the Postman Insights Agent to an existing kubernetes deployment.",
	Long:             "Print a Terraform (HCL) code fragment that can be inserted into a Terraform kubernetes_deployment resource spec to add the Postman Insights Agent as a sidecar container.",
	RunE:             printTerraformFragment,
	PersistentPreRun: kubeCommandPreRun,
}

func printHelmChartFragment(_ *cobra.Command, _ []string) error {
	err := cmderr.CheckAPIKeyAndInsightsProjectID(insightsProjectID)
	if err != nil {
		return err
	}

	apidumpArgs := apidump.ConvertCommonApiDumpFlagsToArgs(printHelmApidumpFlags)
	// Create the Postman Insights Agent sidecar container
	container := createPostmanSidecar(insightsProjectID, false, apidumpArgs)
	// Store it in an array since the fragment will be added to a list of containers
	containerArray := []v1.Container{container}

	containerYamlBytes, err := yaml.Marshal(containerArray)
	if err != nil {
		return err
	}
	containerYaml := indentCodeFragment(containerYamlBytes, 4)

	fmt.Printf("\n%s\n", containerYaml)
	return nil
}

func printTerraformFragment(_ *cobra.Command, _ []string) error {
	err := cmderr.CheckAPIKeyAndInsightsProjectID(insightsProjectID)
	if err != nil {
		return err
	}

	// Create the Postman Insights Agent sidecar container
	hclBlockConfig := createTerraformContainer(insightsProjectID)
	hclBlockConfigString := indentCodeFragment(hclBlockConfig.Bytes(), 4)

	// Print the fragment
	fmt.Printf("\n%s\n", hclBlockConfigString)
	return nil
}

func createTerraformContainer(insightsProjectID string) *hclwrite.File {
	hclConfig := hclwrite.NewEmptyFile()
	rootBody := hclConfig.Body()

	rootBody.AppendUnstructuredTokens(hclwrite.Tokens{
		{
			Type:  hclsyntax.TokenComment,
			Bytes: []byte("# Add this fragment to your 'kubernetes_deployment' resource under 'spec.template.spec'. \n"),
		},
	})

	containerBlock := rootBody.AppendNewBlock("container", []string{})
	containerBody := containerBlock.Body()

	containerBody.SetAttributeValue("name", cty.StringVal("postman-insights-agent"))
	containerBody.SetAttributeValue("image", cty.StringVal(akitaImage))

	containerBody.AppendNewBlock("security_context", []string{}).
		Body().AppendNewBlock("capabilities", []string{}).
		Body().SetAttributeValue("add", cty.ListVal([]cty.Value{
		cty.StringVal("NET_RAW"),
	}))

	argList := []cty.Value{
		cty.StringVal("apidump"),
		cty.StringVal("--project"),
		cty.StringVal(insightsProjectID),
	}
	// If a non default --domain flag was used, specify it for the container as well.
	if rest.Domain != rest.DefaultDomain() {
		argList = append(argList, cty.StringVal("--domain"), cty.StringVal(rest.Domain))
	}
	apidumpArgs := apidump.ConvertCommonApiDumpFlagsToArgs(printTFApidumpFlags)
	for _, arg := range apidumpArgs {
		argList = append(argList, cty.StringVal(arg))
	}
	// Add the args to the container
	args := cty.ListVal(argList)
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

func indentCodeFragment(codeFragmentInBytes []byte, indentLevel int) string {
	// Trim off any extraneous newlines.
	codeFragmentInBytes = bytes.Trim(codeFragmentInBytes, "\n")

	// Indent level prefix
	indentPrefix := strings.Repeat("  ", indentLevel)

	indentedCodeFragment := indentPrefix + strings.ReplaceAll(
		string(codeFragmentInBytes), "\n", "\n"+indentPrefix)

	return indentedCodeFragment
}

func init() {
	printHelmApidumpFlags = apidump.AddCommonApiDumpFlags(printHelmChartFragmentCmd)
	Cmd.AddCommand(printHelmChartFragmentCmd)

	printTFApidumpFlags = apidump.AddCommonApiDumpFlags(printTerraformFragmentCmd)
	Cmd.AddCommand(printTerraformFragmentCmd)
}
