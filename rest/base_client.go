package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

type (
	// Error handling (to call into the telemetry library without
	// creating a circular dependency.)
	APIErrorHandler = func(method string, path string, e error)

	// Authentication handler
	AuthHandler = func(*http.Request) error
)

var (
	// Use a proxy, "" is none. (This is because the flags package doesn't support Optional)
	// May be a URL, a domain name, or an IP address.  HTTP is assumed as the protocol if
	// none is provided.
	ProxyAddress string
	// Accept a server name other than the expected one in the TLS handshake
	ExpectedServerName string

	BaseAPIErrorHandler APIErrorHandler
)

type BaseClient struct {
	host            string
	scheme          string // http or https
	clientID        akid.ClientID
	authHandler     func(*http.Request) error
	apiErrorHandler APIErrorHandler
}

func NewBaseClient(rawHost string, cli akid.ClientID, authHandler AuthHandler, apiErrorHandler APIErrorHandler) *BaseClient {
	if authHandler == nil {
		authHandler = baseAuthHandler
	}

	if apiErrorHandler == nil {
		apiErrorHandler = BaseAPIErrorHandler
	}

	c := BaseClient{
		scheme:          "https",
		host:            rawHost,
		clientID:        cli,
		authHandler:     authHandler,
		apiErrorHandler: apiErrorHandler,
	}
	if viper.GetBool("test_only_disable_https") {
		fmt.Fprintf(os.Stderr, "WARNING: using test backend without SSL\n")
		c.scheme = "http"
	}
	return &c
}

// Report an error to the APIErrorHandler.
func (c *BaseClient) reportError(method string, path string, e error) {
	if c.apiErrorHandler != nil {
		c.apiErrorHandler(method, path, e)
	}
}

// Sends GET request and parses the response as JSON.
func (c *BaseClient) Get(ctx context.Context, path string, resp interface{}) error {
	return c.GetWithQuery(ctx, path, nil, resp)
}

func (c *BaseClient) GetWithQuery(ctx context.Context, path string, query url.Values, resp interface{}) (e error) {
	defer func() {
		if e != nil {
			c.reportError(http.MethodGet, path, e)
		}
	}()
	u := &url.URL{
		Scheme:   c.scheme,
		Host:     c.host,
		Path:     path,
		RawQuery: query.Encode(),
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return errors.Wrap(err, "failed to create HTTP GET request")
	}

	respContent, err := sendRequest(ctx, req, c.authHandler)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(respContent, resp); err != nil {
		return errors.Wrap(err, "failed to unmarshal response body as JSON")
	}
	return nil
}

// Sends POST request after marshaling body into JSON and parses the response as
// JSON.
func (c *BaseClient) Post(ctx context.Context, path string, body interface{}, resp interface{}) (e error) {
	defer func() {
		if e != nil {
			c.reportError(http.MethodPost, path, e)
		}
	}()

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return errors.Wrap(err, "failed to marshal request body into JSON")
	}

	u := &url.URL{
		Scheme: c.scheme,
		Host:   c.host,
		Path:   path,
	}
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return errors.Wrap(err, "failed to create HTTP POST request")
	}
	req.Header.Set("content-type", "application/json")

	respContent, err := sendRequest(ctx, req, c.authHandler)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(respContent, resp); err != nil {
		return errors.Wrap(err, "failed to unmarshal response body as JSON")
	}
	return nil
}
