package rest

import (
	"errors"
	"strings"
)

const apiCatalogNotEnabledMsg = "API Catalog is not enabled for this team. " +
	"Contact your Postman administrator to enable the API Catalog feature."

const apiCatalogFeatureGateMarker = "API Catalog is not enabled"

const discoveryTTLExpiredMarker = "discovery traffic TTL expired"

// MapAPICatalogError checks whether err is the API-Catalog-not-enabled 403
// and, if so, returns a user-friendly error. Otherwise returns the original error.
func MapAPICatalogError(err error) error {
	httpErr, ok := err.(HTTPError)
	if ok && httpErr.StatusCode == 403 && strings.Contains(string(httpErr.Body), apiCatalogFeatureGateMarker) {
		return errors.New(apiCatalogNotEnabledMsg)
	}
	return err
}

// IsDiscoveryTTLExpiredError returns true when err is a 403 HTTP error whose
// body indicates that the discovery traffic TTL has elapsed for the service.
func IsDiscoveryTTLExpiredError(err error) bool {
	httpErr, ok := err.(HTTPError)
	return ok && httpErr.StatusCode == 403 && strings.Contains(string(httpErr.Body), discoveryTTLExpiredMarker)
}
