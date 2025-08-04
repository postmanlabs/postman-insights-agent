package cmderr

import (
	"github.com/akitasoftware/akita-libs/akid"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/cfg"
	"github.com/postmanlabs/postman-insights-agent/env"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
	"github.com/postmanlabs/postman-insights-agent/util"
)

// Checks that a user has configured their Postman API key and returned them.
// If the user has not configured their API key, a user-friendly error message is printed and an error is returned.
func RequirePostmanAPICredentials(explanation string) (string, error) {
	key, _ := cfg.GetPostmanAPIKeyAndEnvironment()
	if key == "" {
		printer.Errorf("No Postman API key configured. %s\n", explanation)
		if env.InDocker() {
			printer.Infof("Please set the POSTMAN_API_KEY environment variable on the Docker command line.\n")
		} else {
			printer.Infof("Please set the POSTMAN_API_KEY environment variable, either in your shell session or prepend it to postman-insights-agent command.\n")
		}
		return "", AkitaErr{Err: errors.New("Could not find a Postman API key to use")}
	}

	return key, nil
}

// Checks that an API key and a project ID are provided, and that the API key is
// valid for the project ID.
func CheckAPIKeyAndInsightsProjectID(projectID string) error {
	// Check for API key.
	_, err := RequirePostmanAPICredentials("The Postman Insights Agent must have an API key in order to capture traces.")
	if err != nil {
		return err
	}

	// Check that project ID is provided.
	if projectID == "" {
		return errors.New("project ID is missing, it must be specified")
	}

	frontClient := rest.NewFrontClient(rest.Domain, telemetry.GetClientID(), nil, nil)
	var serviceID akid.ServiceID
	err = akid.ParseIDAs(projectID, &serviceID)
	if err != nil {
		return errors.Wrap(err, "failed to parse project ID")
	}

	_, err = util.GetServiceNameByServiceID(frontClient, serviceID)
	if err != nil {
		return err
	}

	return nil
}
