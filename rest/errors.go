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
	httpErr, ok := err.(HTTPError)
	if !ok || httpErr.StatusCode != 412 {
		return DiscoveryTTLExpiredError{}, false
	}
	if !strings.Contains(string(httpErr.Body), discoveryTTLExpiredMarker) {
		return DiscoveryTTLExpiredError{}, false
	}

	retryAfter := DefaultDiscoveryTTLRetryAfter
	var body struct {
		Message           string `json:"message"`
		Code              string `json:"code"`
		RetryAfterSeconds int    `json:"retry_after_seconds"`
	}
	if json.Unmarshal(httpErr.Body, &body) == nil {
		if body.RetryAfterSeconds > 0 {
			retryAfter = time.Duration(body.RetryAfterSeconds) * time.Second
		}
		msg := body.Message
		if msg == "" {
			msg = discoveryTTLExpiredMarker
		}
		return DiscoveryTTLExpiredError{
			RetryAfter: retryAfter,
			Message:    msg,
			Code:       body.Code,
		}, true
	}
	return DiscoveryTTLExpiredError{
		RetryAfter: retryAfter,
		Message:    discoveryTTLExpiredMarker,
	}, true
}
