package kube

import (
	"bytes"
	"encoding/base64"
	"text/template"

	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/cmd/internal/cmderr"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
	"github.com/spf13/cobra"
)

var (
	secretFilePathFlag string
	namespaceFlag      string

	// Stores a parsed representation of /template/postman-secret.tmpl.
	secretTemplate *template.Template
)

var secretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Generate a Kubernetes Secret manifest containing your Postman API key",
	Long:  "Generate a Kubernetes Secret manifest containing your Postman API key, and output the result to standard output or a file",
	RunE: func(cmd *cobra.Command, args []string) error {
		key, err := cmderr.RequirePostmanAPICredentials("Postman API key must be specified in the POSTMAN_API_KEY environment variable.")
		if err != nil {
			return err
		}

		output, err := handlePostmanSecretGeneration(namespaceFlag, key)
		if err != nil {
			return err
		}

		// If the secret file path flag hasn't been set, print the generated secret to stdout
		if secretFilePathFlag == "" {
			printer.RawOutput(string(output))
			return nil
		}

		// Otherwise, write the generated secret to the given file path
		err = writeFile(output, secretFilePathFlag)
		if err != nil {
			return cmderr.AkitaErr{Err: errors.Wrapf(err, "Failed to write generated secret to %s", output)}
		}

		printer.Infof("Successfully generated a Kubernetes Secret file for Postman Insights at %s\n", secretFilePathFlag)
		printer.Infof("To apply, run: kubectl apply -f %s\n", secretFilePathFlag)
		return nil
	},
	// Override the parent command's PersistentPreRun to prevent any logs from being printed.
	// This is necessary because the secret command is intended to be used in a pipeline
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// This function overrides the root command preRun so we need to duplicate the domain setup.
		if rest.Domain == "" {
			rest.Domain = rest.DefaultDomain()
		}

		// Initialize the telemetry client, but do not allow any logs to be printed
		telemetry.Init(false)
	},
}

// Represents the input used by secretTemplate
type secretTemplateInput struct {
	Namespace string
	APIKey    string
}

func initSecretTemplate() error {
	var err error
	secretTemplate, err = template.ParseFS(templateFS, "template/postman-secret.tmpl")

	if err != nil {
		return cmderr.AkitaErr{Err: errors.Wrap(err, "failed to parse secret template")}
	}

	return nil
}

// Generates a Kubernetes secret config file for Postman
// On success, the generated output is returned as a string.
func handlePostmanSecretGeneration(namespace, key string) ([]byte, error) {
	err := initSecretTemplate()
	if err != nil {
		return nil, cmderr.AkitaErr{Err: errors.Wrap(err, "failed to initialize secret template")}
	}

	input := secretTemplateInput{
		Namespace: namespace,
		APIKey:    base64.StdEncoding.EncodeToString([]byte(key)),
	}

	buf := bytes.NewBuffer([]byte{})

	err = secretTemplate.Execute(buf, input)
	if err != nil {
		return nil, cmderr.AkitaErr{Err: errors.Wrap(err, "failed to generate template")}
	}

	return buf.Bytes(), nil
}

func init() {
	secretCmd.Flags().StringVarP(
		&namespaceFlag,
		"namespace",
		"n",
		"default",
		"The Kubernetes namespace the secret should be applied to",
	)

	secretCmd.Flags().StringVarP(
		&secretFilePathFlag,
		"file",
		"f",
		"",
		"File to output the generated secret. If not set, the secret will be printed to stdout.",
	)

	Cmd.AddCommand(secretCmd)
}
