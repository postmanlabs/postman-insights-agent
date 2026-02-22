package rest

import (
	"net/http"

	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/cfg"
)

// baseAuthHandler is the default auth handler for all requests.
// It uses PostmanAPIKey from the config to authenticate the request,
// and fallbacks to the Akita API key if PostmanAPIKey is not set.
func baseAuthHandler(req *http.Request) error {
	postmanAPIKey, postmanEnv := cfg.GetPostmanAPIKeyAndEnvironment()

	if postmanAPIKey != "" {
		// Set postman API key as header
		req.Header.Set("x-api-key", postmanAPIKey)

		// Set postman env header if it exists
		if postmanEnv != "" {
			req.Header.Set("x-postman-env", postmanEnv)
		}
	} else {
		// XXX Integration tests still use Akita API keys.
		apiKeyID, apiKeySecret := cfg.GetAPIKeyAndSecret()

		if apiKeyID == "" {
			return errors.New(`Missing or incomplete credentials. Ensure the POSTMAN_INSIGHTS_API_KEY  environment variable has a valid API key for Postman.`)
		}

		if apiKeySecret == "" {
			return errors.New(`Akita API key secret not found, run "login" or use AKITA_API_KEY_SECRET environment variable. If using with Postman, ensure the POSTMAN_API_KEY or POSTMAN_INSIGHTS_API_KEY environment variable has a valid API key for Postman.`)
		}

		req.SetBasicAuth(apiKeyID, apiKeySecret)
	}

	return nil
}

// ApiDumpDaemonsetAuthandler is used by the apidump functions if it is started
// by the kube daemonSet process. It excepts the postmanAPIKey and postmanEnv
// as arguments instead of reading it from the config.
func ApiDumpDaemonsetAuthHandler(postmanAPIKey string, postmanEnv string) func(*http.Request) error {
	return func(req *http.Request) error {
		if postmanAPIKey == "" {
			return errors.New("Postman API key is empty")
		}
		req.Header.Set("x-api-key", postmanAPIKey)

		if postmanEnv != "" {
			req.Header.Set("x-postman-env", postmanEnv)
		}
		return nil
	}
}

// DaemonsetAuthHandler is used by the daemonset process to authenticate the telemetry requests.
// it uses the postmanInsightsVerificationToken to authenticate the request.
func DaemonsetAuthHandler(postmanInsightsVerificationToken string) func(*http.Request) error {
	return func(req *http.Request) error {
		if postmanInsightsVerificationToken == "" {
			return errors.New("Postman Insights verification token is empty")
		}
		req.Header.Set("postman-insights-verification-token", postmanInsightsVerificationToken)
		return nil
	}
}
