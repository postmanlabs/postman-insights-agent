package ec2

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/cmd/internal/cmderr"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
	"github.com/postmanlabs/postman-insights-agent/util"
	"github.com/spf13/cobra"
)

var (
	// Mandatory flag: Postman collection id
	collectionId string
)

var Cmd = &cobra.Command{
	Deprecated:   "This is no longer supported and might be removed in a future release.",
	Use:          "setup",
	Short:        "Add the Postman Insights Agent to the current server.",
	Long:         "The CLI will add the Postman Insights Agent as a systemd service to your current server.",
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
	Cmd.PersistentFlags().StringVar(&collectionId, "collection", "", "Your Postman collection ID")
	Cmd.MarkPersistentFlagRequired("collection")

	Cmd.AddCommand(RemoveFromEC2Cmd)
}

func addAgentToEC2(cmd *cobra.Command, args []string) error {
	// Check for API key
	_, err := cmderr.RequirePostmanAPICredentials("The Postman Insights Agent must have an API key in order to capture traces.")
	if err != nil {
		return err
	}

	// Check collecton Id's existence
	if collectionId == "" {
		return errors.New("Must specify the ID of your collection with the --collection flag.")
	}
	frontClient := rest.NewFrontClient(rest.Domain, telemetry.GetClientID())
	_, err = util.GetOrCreateServiceIDByPostmanCollectionID(frontClient, collectionId)
	if err != nil {
		return err
	}

	return setupAgentForServer(collectionId)
}

func removeAgentFromEC2(cmd *cobra.Command, args []string) error {
	return fmt.Errorf("this command is not yet implemented")
}
