package kube

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/cfg"
	"github.com/postmanlabs/postman-insights-agent/cmd/internal/cmderr"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// The image to use for the Postman Insights Agent sidecar
const akitaImage = "public.ecr.aws/postman/postman-insights-agent:latest"

// Writes the generated secret to the given file path
func writeFile(data []byte, filePath string) error {
	f, err := createFile(filePath)
	if err != nil {
		return cmderr.AkitaErr{
			Err: cmderr.AkitaErr{
				Err: errors.Wrapf(
					err,
					"failed to create file %s",
					filePath,
				),
			},
		}
	}
	defer f.Close()

	_, err = f.Write(data)
	if err != nil {
		return errors.Errorf("failed to write to file %s", filePath)
	}

	return nil
}

// Creates a file at the given path to be used for storing of a Kubernetes configuration object
// If the directory provided does not exist, an error will be returned and the file will not be created
func createFile(path string) (*os.File, error) {
	// Split the output flag value into directory and filename
	outputDir, outputName := filepath.Split(path)

	// Get the absolute path of the output directory
	absOutputDir, err := filepath.Abs(outputDir)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to resolve the absolute path of the output directory")
	}

	// Check that the output directory exists
	if _, statErr := os.Stat(absOutputDir); os.IsNotExist(statErr) {
		return nil, errors.Errorf("output directory %s does not exist", absOutputDir)
	}

	// Check if the output file already exists
	outputFilePath := filepath.Join(absOutputDir, outputName)
	if _, statErr := os.Stat(outputFilePath); statErr == nil {
		return nil, errors.Errorf("output file %s already exists", outputFilePath)
	}

	// Create the output file in the output directory
	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create the output file")
	}

	return outputFile, nil
}

// SidecarOpts configures the Postman Insights Agent sidecar container.
type SidecarOpts struct {
	// Onboarding mode (exactly one of ProjectID, WorkspaceID, or DiscoveryMode should be set)
	ProjectID     string
	WorkspaceID   string
	SystemEnv     string
	DiscoveryMode bool
	ServiceName   string

	// When true, POSTMAN_API_KEY is sourced from a K8s Secret instead of a literal value.
	AddAPIKeyAsSecret bool

	// Discovery metadata (set from manifest + flags)
	ClusterName  string
	WorkloadName string
	WorkloadType string
	Labels       map[string]string

	// Extra apidump CLI args from common flags (e.g. --filter, --rate-limit)
	ApidumpArgs []string
}

func createPostmanSidecar(opts SidecarOpts) v1.Container {
	var args []string
	switch {
	case opts.DiscoveryMode:
		args = []string{"apidump", "--discovery-mode"}
		if opts.ServiceName != "" {
			args = append(args, "--service-name", opts.ServiceName)
		}
	case opts.WorkspaceID != "":
		args = []string{"apidump", "--workspace-id", opts.WorkspaceID, "--system-env", opts.SystemEnv}
	default:
		args = []string{"apidump", "--project", opts.ProjectID}
	}

	if rest.Domain != rest.DefaultDomain() {
		args = append(args, "--domain", rest.Domain)
	}
	args = append(args, opts.ApidumpArgs...)

	pmKey, pmEnv := cfg.GetPostmanAPIKeyAndEnvironment()
	envs := []v1.EnvVar{}

	if opts.AddAPIKeyAsSecret {
		envs = append(envs, v1.EnvVar{
			Name: "POSTMAN_INSIGHTS_API_KEY",
			ValueFrom: &v1.EnvVarSource{
				SecretKeyRef: &v1.SecretKeySelector{
					LocalObjectReference: v1.LocalObjectReference{
						Name: "postman-agent-secrets",
					},
					Key: "postman-api-key",
				},
			},
		})
	} else {
		envs = append(envs, v1.EnvVar{
			Name:  "POSTMAN_INSIGHTS_API_KEY",
			Value: pmKey,
		})
	}

	if pmEnv != "" {
		envs = append(envs, v1.EnvVar{
			Name:  "POSTMAN_ENV",
			Value: pmEnv,
		})
	}

	k8sEnvVars := []v1.EnvVar{
		{
			Name: "POSTMAN_K8S_NODE",
			ValueFrom: &v1.EnvVarSource{
				FieldRef: &v1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
			},
		},
		{
			Name: "POSTMAN_K8S_NAMESPACE",
			ValueFrom: &v1.EnvVarSource{
				FieldRef: &v1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
			},
		},
		{
			Name: "POSTMAN_K8S_POD",
			ValueFrom: &v1.EnvVarSource{
				FieldRef: &v1.ObjectFieldSelector{FieldPath: "metadata.name"},
			},
		},
		{
			Name: "POSTMAN_K8S_HOST_IP",
			ValueFrom: &v1.EnvVarSource{
				FieldRef: &v1.ObjectFieldSelector{FieldPath: "status.hostIP"},
			},
		},
		{
			Name: "POSTMAN_K8S_POD_IP",
			ValueFrom: &v1.EnvVarSource{
				FieldRef: &v1.ObjectFieldSelector{FieldPath: "status.podIP"},
			},
		},
	}
	envs = append(envs, k8sEnvVars...)

	// Discovery metadata env vars -- only relevant in discovery mode where
	// they are used to register the discovered service with the backend.
	if opts.DiscoveryMode {
		if opts.ClusterName != "" {
			envs = append(envs, v1.EnvVar{
				Name:  "POSTMAN_INSIGHTS_CLUSTER_NAME",
				Value: opts.ClusterName,
			})
		}
		if opts.WorkloadName != "" {
			envs = append(envs, v1.EnvVar{
				Name:  "POSTMAN_INSIGHTS_WORKLOAD_NAME",
				Value: opts.WorkloadName,
			})
		}
		if opts.WorkloadType != "" {
			envs = append(envs, v1.EnvVar{
				Name:  "POSTMAN_INSIGHTS_WORKLOAD_TYPE",
				Value: opts.WorkloadType,
			})
		}
		if len(opts.Labels) > 0 {
			labelsJSON, err := json.Marshal(opts.Labels)
			if err == nil {
				envs = append(envs, v1.EnvVar{
					Name:  "POSTMAN_INSIGHTS_LABELS",
					Value: string(labelsJSON),
				})
			}
		}
	}

	cpu := resource.MustParse("200m")
	memory := resource.MustParse("500Mi")

	return v1.Container{
		Name:  "postman-insights-agent",
		Image: akitaImage,
		Env:   envs,
		Args:  args,
		Resources: v1.ResourceRequirements{
			Limits: v1.ResourceList{
				v1.ResourceCPU:    cpu,
				v1.ResourceMemory: memory,
			},
			Requests: v1.ResourceList{
				v1.ResourceCPU:    cpu,
				v1.ResourceMemory: memory,
			},
		},
		SecurityContext: &v1.SecurityContext{
			Capabilities: &v1.Capabilities{Add: []v1.Capability{"NET_RAW"}},
		},
	}
}

// This function overrides the default preRun function in the root command.
// It suppresses the INFO logs printed on start i.e. agent version and telemetry logs
func kubeCommandPreRun(cmd *cobra.Command, args []string) {
	// This function overrides the root command preRun so we need to duplicate the domain setup.
	if rest.Domain == "" {
		rest.Domain = rest.DefaultDomain()
	}

	// Initialize the telemetry client, but do not allow any logs to be printed
	telemetry.Init(false)
}
