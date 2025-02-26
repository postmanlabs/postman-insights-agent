package cri_apis

import (
	"context"
	"encoding/json"
	"net"
	"net/url"

	"github.com/pkg/errors"
)

const (
	// unixProtocol is the network protocol of unix socket.
	unixProtocol = "unix"
)

// getAddressAndDialer returns the address parsed from the given endpoint and a context dialer.
func getAddressAndDialer(endpoint string) (string, func(ctx context.Context, addr string) (net.Conn, error), error) {
	protocol, addr, err := parseEndpointWithFallbackProtocol(endpoint, unixProtocol)
	if err != nil {
		return "", nil, err
	}
	if protocol != unixProtocol {
		return "", nil, errors.New("only support unix socket endpoint")
	}

	return addr, dial, nil
}

// dial creates a network connection to the given address
func dial(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, unixProtocol, addr)
}

// parseEndpointWithFallbackProtocol parses the endpoint and falls back to the given protocol if necessary
func parseEndpointWithFallbackProtocol(endpoint string, fallbackProtocol string) (protocol string, addr string, err error) {
	if protocol, addr, err = parseEndpoint(endpoint); err != nil && protocol == "" {
		fallbackEndpoint := fallbackProtocol + "://" + endpoint
		protocol, addr, err = parseEndpoint(fallbackEndpoint)
	}
	return
}

// parseEndpoint parses the endpoint into protocol and address
func parseEndpoint(endpoint string) (string, string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", "", err
	}

	switch u.Scheme {
	case "tcp":
		return "tcp", u.Host, nil

	case "unix":
		return "unix", u.Path, nil

	case "":
		return "", "", errors.Errorf("using %q as endpoint is deprecated, please consider using full url format", endpoint)

	default:
		return u.Scheme, "", errors.Errorf("protocol %q not supported", u.Scheme)
	}
}

// convertContainerInfo converts a map containing container information into a ContainerInfo struct.
// The map is expected to have a key "info" with a JSON string value representing the container information.
func convertContainerInfo(info map[string]string) (ContainerInfo, error) {
	var containerInfo ContainerInfo

	infoString, ok := info["info"]
	if !ok {
		return ContainerInfo{}, errors.New("info field not found in container info")
	}

	// Unmarshal JSON to struct
	err := json.Unmarshal([]byte(infoString), &containerInfo)
	if err != nil {
		return ContainerInfo{}, err
	}

	return containerInfo, nil
}
