package rest

import (
	"net/http"

	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/cfg"
)

func baseAuthHandler(req *http.Request) error {
	postmanAPIKey, postmanEnv := cfg.GetPostmanAPIKeyAndEnvironment()
	postmanInsightsVerificationToken := cfg.GetPostmanInsightsVerificationToken()

	if postmanAPIKey != "" {
		// Set postman API key as header
		req.Header.Set("x-api-key", postmanAPIKey)

		// Set postman env header if it exists
		if postmanEnv != "" {
			req.Header.Set("x-postman-env", postmanEnv)
		}
	} else if postmanInsightsVerificationToken != "" {
		// Set postman team verification token as header
		req.Header.Set("postman-insights-verification-token ", postmanInsightsVerificationToken)
	} else {
		// XXX Integration tests still use Akita API keys.
		apiKeyID, apiKeySecret := cfg.GetAPIKeyAndSecret()

		if apiKeyID == "" {
			return errors.New(`Missing or incomplete credentials. Ensure the POSTMAN_API_KEY environment variable has a valid API key for Postman.`)
		}

		if apiKeySecret == "" {
			return errors.New(`Akita API key secret not found, run "login" or use AKITA_API_KEY_SECRET environment variable. If using with Postman, ensure the POSTMAN_API_KEY environment variable has a valid API key for Postman.`)
		}

		req.SetBasicAuth(apiKeyID, apiKeySecret)
	}

	return nil
}

func daemonsetAuthHandler(podName string) func(*http.Request) error {
	postmanAPIKey, postmanEnv := cfg.GetPodPostmanAPIKeyAndEnvironment(podName)

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
