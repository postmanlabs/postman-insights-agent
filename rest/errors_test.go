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
