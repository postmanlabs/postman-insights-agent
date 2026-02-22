package kube

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/pkg/errors"
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

	// Shared flags for helm-fragment and tf-fragment
	fragmentDiscoveryMode bool
	fragmentServiceName   string
	fragmentClusterName   string
	fragmentWorkspaceID   string
	fragmentSystemEnv     string
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

func validateFragmentFlags() error {
	if !fragmentDiscoveryMode && insightsProjectID == "" && fragmentWorkspaceID == "" {
		return cmderr.AkitaErr{Err: errors.New("exactly one of --project, --workspace-id, or --discovery-mode must be specified")}
	}
	if fragmentWorkspaceID != "" {
		if fragmentSystemEnv == "" {
			return cmderr.AkitaErr{Err: errors.New("--system-env is required when --workspace-id is specified")}
		}
		if _, err := uuid.Parse(fragmentWorkspaceID); err != nil {
			return cmderr.AkitaErr{Err: errors.Wrap(err, "--workspace-id must be a valid UUID")}
		}
		if _, err := uuid.Parse(fragmentSystemEnv); err != nil {
			return cmderr.AkitaErr{Err: errors.Wrap(err, "--system-env must be a valid UUID")}
		}
	}
	if !fragmentDiscoveryMode && fragmentWorkspaceID == "" {
		if err := cmderr.CheckAPIKeyAndInsightsProjectID(insightsProjectID); err != nil {
			return err
		}
	}
	return nil
}

func buildFragmentSidecarOpts(apidumpArgs []string) SidecarOpts {
	return SidecarOpts{
		ProjectID:         insightsProjectID,
		WorkspaceID:       fragmentWorkspaceID,
		SystemEnv:         fragmentSystemEnv,
		DiscoveryMode:     fragmentDiscoveryMode,
		ServiceName:       fragmentServiceName,
		AddAPIKeyAsSecret: false,
		ClusterName:       fragmentClusterName,
		ApidumpArgs:       apidumpArgs,
	}
}

func printHelmChartFragment(_ *cobra.Command, _ []string) error {
	if err := validateFragmentFlags(); err != nil {
		return err
	}

	apidumpArgs := apidump.ConvertCommonApiDumpFlagsToArgs(printHelmApidumpFlags)
	opts := buildFragmentSidecarOpts(apidumpArgs)
	container := createPostmanSidecar(opts)
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
	if err := validateFragmentFlags(); err != nil {
		return err
	}

	apidumpArgs := apidump.ConvertCommonApiDumpFlagsToArgs(printTFApidumpFlags)
	opts := buildFragmentSidecarOpts(apidumpArgs)
	hclBlockConfig := createTerraformContainer(opts)
	hclBlockConfigString := indentCodeFragment(hclBlockConfig.Bytes(), 4)

	fmt.Printf("\n%s\n", hclBlockConfigString)
	return nil
}

func createTerraformContainer(opts SidecarOpts) *hclwrite.File {
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

	// Build args based on onboarding mode
	var argList []cty.Value
	switch {
	case opts.DiscoveryMode:
		argList = []cty.Value{cty.StringVal("apidump"), cty.StringVal("--discovery-mode")}
		if opts.ServiceName != "" {
			argList = append(argList, cty.StringVal("--service-name"), cty.StringVal(opts.ServiceName))
		}
	case opts.WorkspaceID != "":
		argList = []cty.Value{
			cty.StringVal("apidump"),
			cty.StringVal("--workspace-id"), cty.StringVal(opts.WorkspaceID),
			cty.StringVal("--system-env"), cty.StringVal(opts.SystemEnv),
		}
	default:
		argList = []cty.Value{
			cty.StringVal("apidump"),
			cty.StringVal("--project"), cty.StringVal(opts.ProjectID),
		}
	}
	// If a non default --domain flag was used, specify it for the container as well.
	if rest.Domain != rest.DefaultDomain() {
		argList = append(argList, cty.StringVal("--domain"), cty.StringVal(rest.Domain))
	}
	for _, arg := range opts.ApidumpArgs {
		argList = append(argList, cty.StringVal(arg))
	}
	containerBody.SetAttributeValue("args", cty.ListVal(argList))

	// API key env var
	pmKey, pmEnv := cfg.GetPostmanAPIKeyAndEnvironment()
	apiKeyBody := containerBody.AppendNewBlock("env", []string{}).Body()
	apiKeyBody.SetAttributeValue("name", cty.StringVal("POSTMAN_INSIGHTS_API_KEY"))
	apiKeyBody.SetAttributeValue("value", cty.StringVal(pmKey))

	if pmEnv != "" {
		pmEnvBody := containerBody.AppendNewBlock("env", []string{}).Body()
		pmEnvBody.SetAttributeValue("name", cty.StringVal("POSTMAN_ENV"))
		pmEnvBody.SetAttributeValue("value", cty.StringVal(pmEnv))
	}

	// K8s downward API env vars (via value_from / field_ref in Terraform)
	addTFDownwardAPIEnv := func(name, fieldPath string) {
		envBody := containerBody.AppendNewBlock("env", []string{}).Body()
		envBody.SetAttributeValue("name", cty.StringVal(name))
		vfBody := envBody.AppendNewBlock("value_from", []string{}).Body()
		frBody := vfBody.AppendNewBlock("field_ref", []string{}).Body()
		frBody.SetAttributeValue("field_path", cty.StringVal(fieldPath))
	}
	addTFDownwardAPIEnv("POSTMAN_K8S_NODE", "spec.nodeName")
	addTFDownwardAPIEnv("POSTMAN_K8S_NAMESPACE", "metadata.namespace")
	addTFDownwardAPIEnv("POSTMAN_K8S_POD", "metadata.name")
	addTFDownwardAPIEnv("POSTMAN_K8S_HOST_IP", "status.hostIP")
	addTFDownwardAPIEnv("POSTMAN_K8S_POD_IP", "status.podIP")

	// Discovery metadata env vars -- only relevant in discovery mode.
	if opts.DiscoveryMode {
		addTFStaticEnv := func(name, value string) {
			envBody := containerBody.AppendNewBlock("env", []string{}).Body()
			envBody.SetAttributeValue("name", cty.StringVal(name))
			envBody.SetAttributeValue("value", cty.StringVal(value))
		}
		if opts.ClusterName != "" {
			addTFStaticEnv("POSTMAN_INSIGHTS_CLUSTER_NAME", opts.ClusterName)
		}
		if opts.WorkloadName != "" {
			addTFStaticEnv("POSTMAN_INSIGHTS_WORKLOAD_NAME", opts.WorkloadName)
		}
		if opts.WorkloadType != "" {
			addTFStaticEnv("POSTMAN_INSIGHTS_WORKLOAD_TYPE", opts.WorkloadType)
		}
		if len(opts.Labels) > 0 {
			labelsJSON, err := json.Marshal(opts.Labels)
			if err == nil {
				addTFStaticEnv("POSTMAN_INSIGHTS_LABELS", string(labelsJSON))
			}
		}
	}

	return hclConfig
}

func indentCodeFragment(codeFragmentInBytes []byte, indentLevel int) string {
	// Trim off any extraneous newlines.
	codeFragmentInBytes = bytes.Trim(codeFragmentInBytes, "\n")

	// Indent level prefix
	indentPrefix := strings.Repeat("  ", indentLevel)
	return indentPrefix + strings.ReplaceAll(string(codeFragmentInBytes), "\n", "\n"+indentPrefix)
}

func addFragmentModeFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&fragmentDiscoveryMode, "discovery-mode", false, "Enable auto-discovery without requiring a project ID.")
	cmd.Flags().StringVar(&fragmentServiceName, "service-name", "", "Override the auto-derived service name.")
	cmd.Flags().StringVar(&fragmentClusterName, "cluster-name", "", "Kubernetes cluster name (discovery metadata).")
	cmd.Flags().StringVar(&fragmentWorkspaceID, "workspace-id", "", "Your Postman workspace ID.")
	cmd.Flags().StringVar(&fragmentSystemEnv, "system-env", "", "The system environment UUID. Required with --workspace-id.")
	cmd.MarkFlagsMutuallyExclusive("workspace-id", "discovery-mode")
}

func init() {
	printHelmApidumpFlags = apidump.AddCommonApiDumpFlags(printHelmChartFragmentCmd)
	addFragmentModeFlags(printHelmChartFragmentCmd)
	Cmd.AddCommand(printHelmChartFragmentCmd)

	printTFApidumpFlags = apidump.AddCommonApiDumpFlags(printTerraformFragmentCmd)
	addFragmentModeFlags(printTerraformFragmentCmd)
	Cmd.AddCommand(printTerraformFragmentCmd)
}
