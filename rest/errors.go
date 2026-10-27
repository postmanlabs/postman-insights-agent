package rest

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const apiCatalogNotEnabledMsg = "API Catalog is not enabled for this team. " +
	"Contact your Postman administrator to enable the API Catalog feature."

const apiCatalogFeatureGateMarker = "API Catalog is not enabled"

const (
	discoveryTTLExpiredMarker = "discovery traffic TTL expired"
	workspaceNotLinkedMarker  = "Workspace is not linked to a filesystem"
)

// IngestDisabledError means the backend intentionally refused ingestion
// (412 INGEST_DISABLED), e.g. discovery traffic TTL expired or the workspace
// isn't linked to a filesystem. Wait RetryAfter before retrying.
type IngestDisabledError struct {
	RetryAfter time.Duration
	Message    string
	Code       string
}

func (e IngestDisabledError) Error() string {
	return e.Message
}

// MapAPICatalogError checks whether err is the API-Catalog-not-enabled 403
// and, if so, returns a user-friendly error. Otherwise returns the original error.
func MapAPICatalogError(err error) error {
	httpErr, ok := err.(HTTPError)
	if ok && httpErr.StatusCode == 403 && strings.Contains(string(httpErr.Body), apiCatalogFeatureGateMarker) {
		return errors.New(apiCatalogNotEnabledMsg)
	}
	return err
}

// AsIngestDisabledError reports whether err is (or wraps) an
// IngestDisabledError.
func AsIngestDisabledError(err error) (IngestDisabledError, bool) {
	var ingestErr IngestDisabledError
	if errors.As(err, &ingestErr) {
		return ingestErr, true
	}
	return IngestDisabledError{}, false
}

// IsIngestDisabledError reports whether the backend intentionally refused
// ingestion. Treat it as a skip, not a failure.
func IsIngestDisabledError(err error) bool {
	_, ok := AsIngestDisabledError(err)
	return ok
}

// parseIngestDisabledHTTPError converts a 412 whose body contains marker into
// an IngestDisabledError. marker is the default message, and RetryAfter falls
// back to DefaultIngestRetryAfter when the body has no retry_after_seconds.
func parseIngestDisabledHTTPError(err error, marker string) (IngestDisabledError, bool) {
	httpErr, isHTTP := err.(HTTPError)
	if !isHTTP || httpErr.StatusCode != 412 || !strings.Contains(string(httpErr.Body), marker) {
		return IngestDisabledError{}, false
	}

	ingestErr := IngestDisabledError{RetryAfter: DefaultIngestRetryAfter, Message: marker}
	var body struct {
		Message           string `json:"message"`
		Code              string `json:"code"`
		RetryAfterSeconds int    `json:"retry_after_seconds"`
	}
	if json.Unmarshal(httpErr.Body, &body) != nil {
		return ingestErr, true
	}
	if body.RetryAfterSeconds > 0 {
		ingestErr.RetryAfter = time.Duration(body.RetryAfterSeconds) * time.Second
	}
	if body.Message != "" {
		ingestErr.Message = body.Message
	}
	ingestErr.Code = body.Code
	return ingestErr, true
}
