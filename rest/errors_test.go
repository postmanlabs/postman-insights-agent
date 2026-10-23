package rest

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMapAPICatalogError_MapsMatchingBody(t *testing.T) {
	err := HTTPError{StatusCode: 403, Body: []byte(`{"message":"API Catalog is not enabled for this team"}`)}
	mapped := MapAPICatalogError(err)
	assert.Equal(t, apiCatalogNotEnabledMsg, mapped.Error())
}

func TestMapAPICatalogError_PassThrough_On403_DifferentBody(t *testing.T) {
	err := HTTPError{StatusCode: 403, Body: []byte(`{"message":"you do not have access to this workspace"}`)}
	mapped := MapAPICatalogError(err)
	var httpErr HTTPError
	assert.True(t, errors.As(mapped, &httpErr), "expected original HTTPError to pass through")
	assert.Equal(t, 403, httpErr.StatusCode)
}

func TestMapAPICatalogError_PassThrough_On401(t *testing.T) {
	err := HTTPError{StatusCode: 401, Body: []byte(`unauthorized`)}
	mapped := MapAPICatalogError(err)
	var httpErr HTTPError
	assert.True(t, errors.As(mapped, &httpErr))
	assert.Equal(t, 401, httpErr.StatusCode)
}

func TestMapAPICatalogError_PassThrough_On500(t *testing.T) {
	err := HTTPError{StatusCode: 500, Body: nil}
	mapped := MapAPICatalogError(err)
	var httpErr HTTPError
	assert.True(t, errors.As(mapped, &httpErr))
	assert.Equal(t, 500, httpErr.StatusCode)
}

func TestMapAPICatalogError_PassThrough_OnNonHTTPError(t *testing.T) {
	original := errors.New("some other error")
	mapped := MapAPICatalogError(original)
	assert.Equal(t, original, mapped)
}

func TestMapAPICatalogError_PassThrough_On403_EmptyBody(t *testing.T) {
	err := HTTPError{StatusCode: 403, Body: nil}
	mapped := MapAPICatalogError(err)
	var httpErr HTTPError
	assert.True(t, errors.As(mapped, &httpErr))
	assert.Equal(t, 403, httpErr.StatusCode)
}

func TestParseDiscoveryTTLExpiredHTTPError_Matches412WithRetryAfterAndCode(t *testing.T) {
	err := HTTPError{
		StatusCode: 412,
		Body:       []byte(`{"message":"discovery traffic TTL expired for service \"default/my-svc\"; onboard the service to resume traffic","code":"INGEST_DISABLED","retry_after_seconds":300}`),
	}
	ttlErr, ok := parseDiscoveryTTLExpiredHTTPError(err)
	assert.True(t, ok)
	assert.Equal(t, 300*time.Second, ttlErr.RetryAfter)
	assert.Equal(t, "INGEST_DISABLED", ttlErr.Code)
	assert.Contains(t, ttlErr.Message, discoveryTTLExpiredMarker)
}

func TestParseDiscoveryTTLExpiredHTTPError_DefaultRetryWhenMissing(t *testing.T) {
	err := HTTPError{
		StatusCode: 412,
		Body:       []byte(`{"message":"discovery traffic TTL expired","code":"INGEST_DISABLED"}`),
	}
	ttlErr, ok := parseDiscoveryTTLExpiredHTTPError(err)
	assert.True(t, ok)
	assert.Equal(t, DefaultIngestRetryAfter, ttlErr.RetryAfter)
	assert.Equal(t, "INGEST_DISABLED", ttlErr.Code)
}

func TestParseDiscoveryTTLExpiredHTTPError_NoMatch_403(t *testing.T) {
	err := HTTPError{
		StatusCode: 403,
		Body:       []byte(`{"message":"discovery traffic TTL expired for service \"default/my-svc\""}`),
	}
	_, ok := parseDiscoveryTTLExpiredHTTPError(err)
	assert.False(t, ok)
}

func TestParseDiscoveryTTLExpiredHTTPError_NoMatch_412DifferentBody(t *testing.T) {
	err := HTTPError{
		StatusCode: 412,
		Body:       []byte(`{"message":"ingestion is temporarily disabled"}`),
	}
	_, ok := parseDiscoveryTTLExpiredHTTPError(err)
	assert.False(t, ok)
}

func TestAsDiscoveryTTLExpiredError_TypedError(t *testing.T) {
	original := DiscoveryTTLExpiredError{
		RetryAfter: time.Minute,
		Message:    "ttl done",
		Code:       "INGEST_DISABLED",
	}
	ttlErr, ok := AsDiscoveryTTLExpiredError(original)
	assert.True(t, ok)
	assert.Equal(t, time.Minute, ttlErr.RetryAfter)
	assert.Equal(t, "INGEST_DISABLED", ttlErr.Code)
}

func TestAsDiscoveryTTLExpiredError_WrappedTypedError(t *testing.T) {
	original := DiscoveryTTLExpiredError{RetryAfter: time.Minute, Message: "ttl done", Code: "INGEST_DISABLED"}
	wrapped := fmt.Errorf("outer: %w", original)
	ttlErr, ok := AsDiscoveryTTLExpiredError(wrapped)
	assert.True(t, ok)
	assert.Equal(t, time.Minute, ttlErr.RetryAfter)
	assert.Equal(t, "INGEST_DISABLED", ttlErr.Code)
}

func TestAsDiscoveryTTLExpiredError_NoMatch_HTTPError(t *testing.T) {
	err := HTTPError{
		StatusCode: 412,
		Body:       []byte(`{"message":"discovery traffic TTL expired"}`),
	}
	_, ok := AsDiscoveryTTLExpiredError(err)
	assert.False(t, ok, "HTTPError must be parsed in RegisterDiscoveredService, not via As*")
}

func TestParseWorkspaceNotLinkedHTTPError_412WithRetryAfter_UsesBodyRetryAfter(t *testing.T) {
	err := HTTPError{
		StatusCode: 412,
		Body:       []byte(`{"message":"Workspace is not linked to a filesystem","code":"INGEST_DISABLED","retry_after_seconds":120}`),
	}
	wsErr, ok := parseWorkspaceNotLinkedHTTPError(err)
	assert.True(t, ok)
	assert.Equal(t, 2*time.Minute, wsErr.RetryAfter)
	assert.Equal(t, "INGEST_DISABLED", wsErr.Code)
	assert.Equal(t, "Workspace is not linked to a filesystem", wsErr.Message)
}

func TestParseWorkspaceNotLinkedHTTPError_412WithoutRetryAfter_UsesDefault(t *testing.T) {
	err := HTTPError{StatusCode: 412, Body: []byte(`{"message":"Workspace is not linked to a filesystem"}`)}
	wsErr, ok := parseWorkspaceNotLinkedHTTPError(err)
	assert.True(t, ok)
	assert.Equal(t, DefaultIngestRetryAfter, wsErr.RetryAfter)
}

func TestParseWorkspaceNotLinkedHTTPError_OtherBodyOrStatus_NoMatch(t *testing.T) {
	cases := map[string]HTTPError{
		"412 discovery TTL body": {StatusCode: 412, Body: []byte(`{"message":"discovery traffic TTL expired"}`)},
		"412 unrelated body":     {StatusCode: 412, Body: []byte(`{"message":"ingestion is temporarily disabled"}`)},
		"400 workspace body":     {StatusCode: 400, Body: []byte(`{"message":"Workspace is not linked to a filesystem"}`)},
	}
	for name, err := range cases {
		t.Run(name, func(t *testing.T) {
			_, ok := parseWorkspaceNotLinkedHTTPError(err)
			assert.False(t, ok)
		})
	}
}

func TestParseDiscoveryTTLExpiredHTTPError_412WorkspaceBody_NoMatch(t *testing.T) {
	err := HTTPError{StatusCode: 412, Body: []byte(`{"message":"Workspace is not linked to a filesystem"}`)}
	_, ok := parseDiscoveryTTLExpiredHTTPError(err)
	assert.False(t, ok)
}

func TestIsIngestDisabledError_WrappedTypedErrors_ReturnsTrue(t *testing.T) {
	assert.True(t, IsIngestDisabledError(fmt.Errorf("outer: %w", WorkspaceNotLinkedError{})))
	assert.True(t, IsIngestDisabledError(fmt.Errorf("outer: %w", DiscoveryTTLExpiredError{})))
}

func TestIsIngestDisabledError_UnparsedHTTPError_ReturnsFalse(t *testing.T) {
	err := HTTPError{StatusCode: 412, Body: []byte(`{"message":"Workspace is not linked to a filesystem"}`)}
	assert.False(t, IsIngestDisabledError(err))
}
