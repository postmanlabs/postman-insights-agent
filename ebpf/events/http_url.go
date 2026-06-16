// SPDX-License-Identifier: Apache-2.0

package events

import (
	"net"
	"strconv"
	"strings"

	"github.com/akitasoftware/akita-libs/akinet"
)

// enrichHTTPRequestURL fills missing scheme/host on HTTP/2 (and HTTP/1) requests
// when HPACK omits :authority (common on gRPC) or the Java agent cannot supply
// a socket tuple (fd=-1).
func enrichHTTPRequestURL(
	req *akinet.HTTPRequest,
	direction uint8,
	localIP net.IP,
	localPort int,
	remoteIP net.IP,
	remotePort int,
) {
	if req == nil || req.URL == nil {
		return
	}

	host := req.Host
	if host == "" {
		host = req.Header.Get("Host")
	}
	if host == "" && localPort > 0 {
		var ip net.IP
		var port int
		switch direction {
		case DirIngress:
			ip, port = localIP, localPort
		case DirEgress:
			ip, port = remoteIP, remotePort
		}
		if ip != nil && !ip.IsUnspecified() && port > 0 {
			host = net.JoinHostPort(ip.String(), strconv.Itoa(port))
		}
	}
	if host != "" {
		req.Host = host
		req.URL.Host = host
		if req.Header.Get("Host") == "" {
			req.Header.Set("Host", host)
		}
	}

	if req.URL.Scheme == "" {
		ct := req.Header.Get("content-type")
		if strings.HasPrefix(ct, "application/grpc") {
			req.URL.Scheme = "https"
		}
	}
}
