package rest

import (
	"errors"
	"testing"

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

func TestIsDiscoveryTTLExpiredError_MatchesMarkerIn403(t *testing.T) {
	err := HTTPError{
		StatusCode: 403,
		Body:       []byte(`{"message":"discovery traffic TTL expired for service \"default/my-svc\"; onboard the service to resume traffic"}`),
	}
	assert.True(t, IsDiscoveryTTLExpiredError(err))
}

func TestIsDiscoveryTTLExpiredError_NoMatch_403DifferentBody(t *testing.T) {
	err := HTTPError{
		StatusCode: 403,
		Body:       []byte(`{"message":"you do not have access to this workspace"}`),
	}
	assert.False(t, IsDiscoveryTTLExpiredError(err))
}

func TestIsDiscoveryTTLExpiredError_NoMatch_403EmptyBody(t *testing.T) {
	err := HTTPError{StatusCode: 403, Body: nil}
	assert.False(t, IsDiscoveryTTLExpiredError(err))
}

func TestIsDiscoveryTTLExpiredError_NoMatch_DifferentStatusCode(t *testing.T) {
	err := HTTPError{
		StatusCode: 412,
		Body:       []byte(`discovery traffic TTL expired`),
	}
	assert.False(t, IsDiscoveryTTLExpiredError(err))
}

func TestIsDiscoveryTTLExpiredError_NoMatch_NonHTTPError(t *testing.T) {
	err := errors.New("discovery traffic TTL expired")
	assert.False(t, IsDiscoveryTTLExpiredError(err))
}
