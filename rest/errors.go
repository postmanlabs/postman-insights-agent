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

// DiscoveryTTLExpiredError is returned when /discover rejects a service because
// its discovery traffic TTL has elapsed. RetryAfter is the cooldown the agent
// should wait before calling /discover again for the same workload.
type DiscoveryTTLExpiredError struct {
	RetryAfter time.Duration
	Message    string
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

// IsDiscoveryTTLExpiredError returns true when err indicates that the discovery
// traffic TTL has elapsed for the service. Accepts 412 (current) and 403
// (legacy backends).
func IsDiscoveryTTLExpiredError(err error) bool {
	_, ok := AsDiscoveryTTLExpiredError(err)
	return ok
}

// AsDiscoveryTTLExpiredError extracts TTL-expiry details from err when present.
// Prefer this over IsDiscoveryTTLExpiredError when the retry_after cooldown is needed.
func AsDiscoveryTTLExpiredError(err error) (DiscoveryTTLExpiredError, bool) {
	var ttlErr DiscoveryTTLExpiredError
	if errors.As(err, &ttlErr) {
		return ttlErr, true
	}

	httpErr, ok := err.(HTTPError)
	if !ok {
		return DiscoveryTTLExpiredError{}, false
	}
	// 412 is the current status; 403 is kept for older backends.
	if httpErr.StatusCode != 412 && httpErr.StatusCode != 403 {
		return DiscoveryTTLExpiredError{}, false
	}
	if !strings.Contains(string(httpErr.Body), discoveryTTLExpiredMarker) {
		return DiscoveryTTLExpiredError{}, false
	}

	retryAfter := DefaultDiscoveryTTLRetryAfter
	var body struct {
		Message           string `json:"message"`
		RetryAfterSeconds int    `json:"retry_after_seconds"`
	}
	if json.Unmarshal(httpErr.Body, &body) == nil {
		if body.RetryAfterSeconds > 0 {
			retryAfter = time.Duration(body.RetryAfterSeconds) * time.Second
		}
		if body.Message != "" {
			return DiscoveryTTLExpiredError{RetryAfter: retryAfter, Message: body.Message}, true
		}
	}
	return DiscoveryTTLExpiredError{
		RetryAfter: retryAfter,
		Message:    discoveryTTLExpiredMarker,
	}, true
}
