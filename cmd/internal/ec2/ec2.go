package ec2

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/cmd/internal/apidump"
	"github.com/postmanlabs/postman-insights-agent/cmd/internal/cmderr"
	"github.com/spf13/cobra"
)

var (
	// Postman Insights project id
	projectID    string
	apidumpFlags *apidump.CommonApidumpFlags

	// Discovery mode flags
	discoveryMode bool
	serviceName   string

	// Workspace onboarding flags
	workspaceID string
	systemEnv   string

	// Overwrite the existing service file and don't prompt the user
	forceOverwrite bool
)

var Cmd = &cobra.Command{
	Use:          "ec2",
	Short:        "Add the Postman Insights Agent to the EC2 server.",
	Long:         "The CLI will add the Postman Insights Agent as a systemd service to your current EC2 server.",
	SilenceUsage: true,
	RunE:         addAgentToEC2,
}

// 'postman-insights-agent ec2' should default to 'postman-insights-agent ec2 setup'
var SetupInEC2Cmd = &cobra.Command{
	Use:          "setup",
	Short:        Cmd.Short,
	Long:         Cmd.Long,
	SilenceUsage: true,
	RunE:         addAgentToEC2,
}

var RemoveFromEC2Cmd = &cobra.Command{
	Use:          "remove",
	Short:        "Remove the Postman Insights Agent from EC2.",
	Long:         "Remove a previously installed Postman Insights agent from an EC2 server.",
	SilenceUsage: true,
	RunE:         removeAgentFromEC2,

	// Temporarily hide from users until complete
	Hidden: true,
}

func init() {
	Cmd.PersistentFlags().StringVar(&projectID, "project", "", "Your Insights Project ID")

	// Discovery mode flags
	Cmd.PersistentFlags().BoolVar(&discoveryMode, "discovery-mode", false, "Enable auto-discovery without requiring a project ID.")
	Cmd.PersistentFlags().StringVar(&serviceName, "service-name", "", "Override the auto-derived service name.")

	// Workspace onboarding flags
	Cmd.PersistentFlags().StringVar(&workspaceID, "workspace-id", "", "Your Postman workspace ID.")
	Cmd.PersistentFlags().StringVar(&systemEnv, "system-env", "", "The system environment UUID. Required with --workspace-id.")
	Cmd.MarkFlagsMutuallyExclusive("project", "workspace-id", "discovery-mode")
	Cmd.MarkFlagsRequiredTogether("workspace-id", "system-env")

	apidumpFlags = apidump.AddCommonApiDumpFlags(Cmd)

	SetupInEC2Cmd.PersistentFlags().BoolVarP(&forceOverwrite, "force", "f", false, "If the service files already exist, overwrite them without asking for confirmation")

	Cmd.AddCommand(SetupInEC2Cmd)
	Cmd.AddCommand(RemoveFromEC2Cmd)
}

func validateEC2Flags() error {
	if !discoveryMode && projectID == "" && workspaceID == "" {
		return cmderr.AkitaErr{Err: errors.New("exactly one of --project, --workspace-id, or --discovery-mode must be specified")}
	}
	if workspaceID != "" {
		if _, err := uuid.Parse(workspaceID); err != nil {
			return cmderr.AkitaErr{Err: errors.Wrap(err, "--workspace-id must be a valid UUID")}
		}
		if _, err := uuid.Parse(systemEnv); err != nil {
			return cmderr.AkitaErr{Err: errors.Wrap(err, "--system-env must be a valid UUID")}
		}
	}
	// API key is required for all onboarding modes.
	if _, err := cmderr.RequirePostmanAPICredentials("The Postman Insights Agent must have an API key in order to capture traces."); err != nil {
		return err
	}
	// In project mode, also validate that the project exists.
	if !discoveryMode && workspaceID == "" {
		if err := cmderr.CheckAPIKeyAndInsightsProjectID(projectID); err != nil {
			return err
		}
	}
	return nil
}

func addAgentToEC2(cmd *cobra.Command, args []string) error {
	if err := validateEC2Flags(); err != nil {
		return err
	}

	return setupAgentForServer()
}

func removeAgentFromEC2(cmd *cobra.Command, args []string) error {
	return fmt.Errorf("this command is not yet implemented")
}
