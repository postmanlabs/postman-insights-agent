package kube

import (
	"bytes"
	"fmt"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/go-utils/optionals"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/cmd/internal/apidump"
	"github.com/postmanlabs/postman-insights-agent/cmd/internal/cmderr"
	"github.com/postmanlabs/postman-insights-agent/cmd/internal/kube/injector"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
	"github.com/postmanlabs/postman-insights-agent/util"
	"github.com/spf13/cobra"
)

var (
	// The target Yaml file to be injected
	// This is required for execution of injectCmd
	injectFileNameFlag string
	// The output file to write the injected Yaml to
	// If not set, injectCmd will default to printing the output to stdout
	injectOutputFlag string
	// Represents the options for generating a secret
	// When set to "false" or left empty, injectCmd will not generate a secret
	// When set to "true", injectCmd will prepend a secret to each injectable namespace found in the file to inject (injectFileNameFlag)
	// Otherwise, injectCmd will treat secretInjectFlag as the file path all secrets should be generated to
	secretInjectFlag string

	apidumpFlags *apidump.CommonApidumpFlags
)

var injectCmd = &cobra.Command{
	Use:   "inject",
	Short: "Inject the Postman Insights Agent into a Kubernetes deployment",
	Long:  "Inject the Postman Insights Agent into a Kubernetes deployment or set of deployments, and output the result to stdout or a file",
	RunE: func(_ *cobra.Command, args []string) error {
		// Validate onboarding mode: exactly one of project, workspace-id, or discovery-mode.
		if !onboardDiscoveryMode && insightsProjectID == "" && onboardWorkspaceID == "" {
			return cmderr.AkitaErr{
				Err: errors.New("exactly one of --project, --workspace-id, or --discovery-mode must be specified"),
			}
		}
		if onboardWorkspaceID != "" {
			if _, err := uuid.Parse(onboardWorkspaceID); err != nil {
				return cmderr.AkitaErr{Err: errors.Wrap(err, "--workspace-id must be a valid UUID")}
			}
			if _, err := uuid.Parse(onboardSystemEnv); err != nil {
				return cmderr.AkitaErr{Err: errors.Wrap(err, "--system-env must be a valid UUID")}
			}
		}
		// API key is required for all onboarding modes.
		if _, err := cmderr.RequirePostmanAPICredentials("The Postman Insights Agent must have an API key in order to capture traces."); err != nil {
			return err
		}
		// In project mode, also validate that the project exists.
		if !onboardDiscoveryMode && onboardWorkspaceID == "" {
			if err := lookupService(insightsProjectID); err != nil {
				return err
			}
		}

		secretOpts := resolveSecretGenerationOptions(secretInjectFlag)

		// To avoid users unintentionally attempting to apply injected Deployments via pipeline without
		// their dependent Secrets, require that the user explicitly specify an output file.
		if secretOpts.ShouldInject && secretOpts.Filepath.IsSome() && injectOutputFlag == "" {
			printer.Errorln("Cannot specify a Secret file path without an output file (using --output or -o)")
			printer.Infoln("To generate a Secret file on its own, use `postman-insights-agent kube secret`")
			return cmderr.AkitaErr{
				Err: errors.New("invalid flag usage"),
			}
		}

		// Create the injector which reads from the Kubernetes YAML file specified by the user
		injectr, err := injector.FromYAML(injectFileNameFlag)
		if err != nil {
			return cmderr.AkitaErr{
				Err: errors.Wrapf(
					err,
					"Failed to read injection file %s",
					injectFileNameFlag,
				),
			}
		}

		// Extract deployment metadata for discovery env vars
		meta, err := injectr.InjectableDeploymentMeta()
		if err != nil {
			return cmderr.AkitaErr{Err: errors.Wrap(err, "Failed to read deployment metadata")}
		}

		// Generate a secret for each namespace in the deployment if the user specified secret generation
		secretBuf := new(bytes.Buffer)
		if secretOpts.ShouldInject {
			namespaces, err := injectr.InjectableNamespaces()
			if err != nil {
				return err
			}

			key, err := cmderr.RequirePostmanAPICredentials("Postman API credentials are required to generate secret.")
			if err != nil {
				return err
			}

			for _, namespace := range namespaces {
				r, err := handlePostmanSecretGeneration(namespace, key)
				if err != nil {
					return err
				}

				secretBuf.WriteString("---\n")
				secretBuf.Write(r)
			}
		}

		// Create the output buffer
		out := new(bytes.Buffer)

		// Either write the secret to a file or prepend it to the output
		if secretFilePath, exists := secretOpts.Filepath.Get(); exists {
			err = writeFile(secretBuf.Bytes(), secretFilePath)
			if err != nil {
				return err
			}

			printer.Infof("Kubernetes Secret generated to %s\n", secretFilePath)
		} else {
			// Assign the secret to the output buffer
			// We do this so that the secret is written before any injected Deployment resources that depend on it
			out = secretBuf
		}

		apidumpArgs := apidump.ConvertCommonApiDumpFlagsToArgs(apidumpFlags)
		container := createPostmanSidecar(SidecarOpts{
			ProjectID:         insightsProjectID,
			WorkspaceID:       onboardWorkspaceID,
			SystemEnv:         onboardSystemEnv,
			DiscoveryMode:     onboardDiscoveryMode,
			ServiceName:       onboardServiceName,
			AddAPIKeyAsSecret: secretOpts.ShouldInject,
			ClusterName:       onboardClusterName,
			WorkloadName:      meta.Name,
			WorkloadType:      "Deployment",
			Labels:            meta.Labels,
			ApidumpArgs:       apidumpArgs,
		})

		rawInjected, err := injector.ToRawYAML(injectr, container)
		if err != nil {
			return cmderr.AkitaErr{Err: errors.Wrap(err, "Failed to inject sidecars")}
		}
		out.Write(rawInjected)

		if injectOutputFlag == "" {
			printer.Stdout.RawOutput(out.String())
			return nil
		}

		if err := writeFile(out.Bytes(), injectOutputFlag); err != nil {
			return err
		}
		printer.Infof("Injected YAML written to %s\n", injectOutputFlag)

		return nil
	},
	PersistentPreRun: kubeCommandPreRun,
}

// A parsed representation of the `--secret` option.
type secretGenerationOptions struct {
	// Whether to inject a secret
	ShouldInject bool
	// The path to the secret file
	Filepath optionals.Optional[string]
}

// Parses the given value for the `--secret` option.
func resolveSecretGenerationOptions(flagValue string) secretGenerationOptions {
	if flagValue == "" || flagValue == "false" {
		return secretGenerationOptions{
			ShouldInject: false,
			Filepath:     optionals.None[string](),
		}
	}

	if flagValue == "true" {
		return secretGenerationOptions{
			ShouldInject: true,
			Filepath:     optionals.None[string](),
		}
	}

	return secretGenerationOptions{
		ShouldInject: true,
		Filepath:     optionals.Some(flagValue),
	}
}

// Check if service exists or not (and this API key has access).
func lookupService(insightsProjectID string) error {
	var serviceID akid.ServiceID

	err := akid.ParseIDAs(insightsProjectID, &serviceID)
	if err != nil {
		return fmt.Errorf("Can't parse %q as project ID.", insightsProjectID)
	}

	frontClient := rest.NewFrontClient(rest.Domain, telemetry.GetClientID(), nil, nil)

	_, err = util.GetServiceNameByServiceID(frontClient, serviceID)
	return err
}

func init() {
	// `kube inject` command level flags
	injectCmd.Flags().StringVarP(
		&injectFileNameFlag,
		"file",
		"f",
		"",
		"Path to the Kubernetes YAML file to be injected, or - for standard input. This should contain a Deployment object.",
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

	addOnboardingModeFlags(injectCmd)

	apidumpFlags = apidump.AddCommonApiDumpFlags(injectCmd)

	Cmd.AddCommand(injectCmd)
}
