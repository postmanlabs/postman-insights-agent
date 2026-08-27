package trace

import (
	"context"
	"errors"
	"testing"

	"github.com/postmanlabs/postman-insights-agent/rest"
)

func TestClassifyUploadError(t *testing.T) {
	testCases := []struct {
		name string
		err  error
		want UploadStatus
	}{
		{"nil error is success", nil, UploadSuccess},
		{"429 is throttled", rest.HTTPError{StatusCode: 429}, UploadThrottled},
		{"401 is a client error", rest.HTTPError{StatusCode: 401}, UploadClientError},
		{"404 is a client error", rest.HTTPError{StatusCode: 404}, UploadClientError},
		{"500 is a server error", rest.HTTPError{StatusCode: 500}, UploadServerError},
		{"503 is a server error", rest.HTTPError{StatusCode: 503}, UploadServerError},
		{"timeout is a network error", context.DeadlineExceeded, UploadNetworkError},
		{"unknown error is a network error", errors.New("dial tcp: refused"), UploadNetworkError},
		{
			// The upload path wraps errors before logging them, so classification
			// has to survive wrapping.
			"wrapped HTTP error keeps its class",
			errors.Join(errors.New("upload failed"), rest.HTTPError{StatusCode: 503}),
			UploadServerError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyUploadError(tc.err); got != tc.want {
				t.Fatalf("ClassifyUploadError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}
