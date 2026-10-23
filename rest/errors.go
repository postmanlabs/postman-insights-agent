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

const discoveryTTLExpiredMarker = "discovery traffic TTL expired"

// DiscoveryTTLExpiredError is returned by RegisterDiscoveredService when the
// backend rejects a service because its discovery traffic TTL has elapsed.
// RetryAfter is the cooldown the agent should wait before calling /discover
// again for the same workload.
type DiscoveryTTLExpiredError struct {
	RetryAfter time.Duration
	Message    string
	Code       string
}

func (e DiscoveryTTLExpiredError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return discoveryTTLExpiredMarker
}

const workspaceNotLinkedMarker = "Workspace is not linked to a filesystem"

// WorkspaceNotLinkedError means the workspace isn't linked to a filesystem, so
// it isn't monitored. Wait RetryAfter before retrying.
type WorkspaceNotLinkedError struct {
	RetryAfter time.Duration
	Message    string
	Code       string
}

func (e WorkspaceNotLinkedError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return workspaceNotLinkedMarker
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

// AsDiscoveryTTLExpiredError reports whether err is (or wraps) a
// DiscoveryTTLExpiredError returned by RegisterDiscoveredService.
func AsDiscoveryTTLExpiredError(err error) (DiscoveryTTLExpiredError, bool) {
	var ttlErr DiscoveryTTLExpiredError
	if errors.As(err, &ttlErr) {
		return ttlErr, true
	}
	return DiscoveryTTLExpiredError{}, false
}

// parseDiscoveryTTLExpiredHTTPError converts a 412 /discover response into a
// DiscoveryTTLExpiredError. Returns false for any other error.
func parseDiscoveryTTLExpiredHTTPError(err error) (DiscoveryTTLExpiredError, bool) {
	retryAfter, msg, code, ok := parseIngestDisabledHTTPError(err, discoveryTTLExpiredMarker)
	return DiscoveryTTLExpiredError{RetryAfter: retryAfter, Message: msg, Code: code}, ok
}

// AsWorkspaceNotLinkedError reports whether err is (or wraps) a
// WorkspaceNotLinkedError.
func AsWorkspaceNotLinkedError(err error) (WorkspaceNotLinkedError, bool) {
	var wsErr WorkspaceNotLinkedError
	if errors.As(err, &wsErr) {
		return wsErr, true
	}
	return WorkspaceNotLinkedError{}, false
}

// IsIngestDisabledError reports whether the backend intentionally refused
// ingestion. Treat it as a skip, not a failure.
func IsIngestDisabledError(err error) bool {
	_, ttlExpired := AsDiscoveryTTLExpiredError(err)
	_, workspaceNotLinked := AsWorkspaceNotLinkedError(err)
	return ttlExpired || workspaceNotLinked
}

func parseWorkspaceNotLinkedHTTPError(err error) (WorkspaceNotLinkedError, bool) {
	retryAfter, msg, code, ok := parseIngestDisabledHTTPError(err, workspaceNotLinkedMarker)
	return WorkspaceNotLinkedError{RetryAfter: retryAfter, Message: msg, Code: code}, ok
}

// parseIngestDisabledHTTPError falls back to DefaultIngestRetryAfter
// when the body has no retry_after_seconds.
func parseIngestDisabledHTTPError(err error, marker string) (retryAfter time.Duration, msg, code string, ok bool) {
	httpErr, isHTTP := err.(HTTPError)
	if !isHTTP || httpErr.StatusCode != 412 || !strings.Contains(string(httpErr.Body), marker) {
		return 0, "", "", false
	}

	retryAfter, msg = DefaultIngestRetryAfter, marker
	var body struct {
		Message           string `json:"message"`
		Code              string `json:"code"`
		RetryAfterSeconds int    `json:"retry_after_seconds"`
	}
	if json.Unmarshal(httpErr.Body, &body) != nil {
		return retryAfter, msg, "", true
	}
	if body.RetryAfterSeconds > 0 {
		retryAfter = time.Duration(body.RetryAfterSeconds) * time.Second
	}
	if body.Message != "" {
		msg = body.Message
	}
	return retryAfter, msg, body.Code, true
}
