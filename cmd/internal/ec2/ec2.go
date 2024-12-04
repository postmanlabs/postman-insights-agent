package ec2

import (
	"fmt"

	"github.com/postmanlabs/postman-insights-agent/cmd/internal/apidump"
	"github.com/postmanlabs/postman-insights-agent/cmd/internal/cmderr"
	"github.com/spf13/cobra"
)

var (
	// Postman Insights project id
	projectID    string
	apidumpFlags apidump.CommonApidumpFlags
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
	Cmd.MarkPersistentFlagRequired("project")

	// initialize common apidump flags as flags for the ecs add command
	apidumpFlags = apidump.AddCommonApiDumpFlags(Cmd)

	Cmd.AddCommand(SetupInEC2Cmd)
	Cmd.AddCommand(RemoveFromEC2Cmd)
}

func addAgentToEC2(cmd *cobra.Command, args []string) error {
	// Check if the API key and Insights project ID are valid
	err := cmderr.CheckAPIKeyAndInsightsProjectID(projectID)
	if err != nil {
		return err
	}

	return setupAgentForServer(projectID)
}

func removeAgentFromEC2(cmd *cobra.Command, args []string) error {
	return fmt.Errorf("this command is not yet implemented")
}
