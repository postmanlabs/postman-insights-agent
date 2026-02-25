package rest

import (
	"errors"
	"strings"
)

const apiCatalogNotEnabledMsg = "API Catalog is not enabled for this team. " +
	"Contact your Postman administrator to enable the API Catalog feature."

const apiCatalogFeatureGateMarker = "API Catalog is not enabled"

// MapAPICatalogError checks whether err is the API-Catalog-not-enabled 403
// and, if so, returns a user-friendly error. Otherwise returns the original error.
func MapAPICatalogError(err error) error {
	httpErr, ok := err.(HTTPError)
	if ok && httpErr.StatusCode == 403 && strings.Contains(string(httpErr.Body), apiCatalogFeatureGateMarker) {
		return errors.New(apiCatalogNotEnabledMsg)
	}
	return err
}
