// SPDX-License-Identifier: Apache-2.0

package events

import (
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/akitasoftware/akita-libs/akinet"
)

func TestEnrichHTTPRequestURL_FromHostHeader(t *testing.T) {
	req := akinet.HTTPRequest{
		URL:    &url.URL{Scheme: "https", Path: "/phase5c2.Greeter/SayHello"},
		Header: http.Header{"Host": []string{"localhost:8446"}},
	}
	enrichHTTPRequestURL(&req, DirIngress, nil, 0, nil, 0)
	if req.URL.Host != "localhost:8446" {
		t.Fatalf("URL.Host = %q, want localhost:8446", req.URL.Host)
	}
}

func TestEnrichHTTPRequestURL_FromSocketIngress(t *testing.T) {
	req := akinet.HTTPRequest{
		URL:    &url.URL{Scheme: "https", Path: "/svc/Method"},
		Header: http.Header{"Content-Type": []string{"application/grpc"}},
	}
	local := net.ParseIP("10.0.0.5")
	enrichHTTPRequestURL(&req, DirIngress, local, 8446, net.ParseIP("10.0.0.9"), 54321)
	if req.URL.Host != "10.0.0.5:8446" {
		t.Fatalf("URL.Host = %q, want 10.0.0.5:8446", req.URL.Host)
	}
}

func TestEnrichHTTPRequestURL_PreservesQueryString(t *testing.T) {
	req := akinet.HTTPRequest{
		URL: &url.URL{
			Scheme:   "https",
			Path:     "/phase5b2",
			RawQuery: "q=test&page=2",
		},
		Header: http.Header{"Host": []string{"dotnet-service:8443"}},
	}
	enrichHTTPRequestURL(&req, DirIngress, net.ParseIP("10.0.0.5"), 8443, nil, 0)
	if req.URL.RawQuery != "q=test&page=2" {
		t.Fatalf("RawQuery = %q, want q=test&page=2", req.URL.RawQuery)
	}
	got := req.URL.String()
	want := "https://dotnet-service:8443/phase5b2?q=test&page=2"
	if got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
}
