package pcap

import (
	"net"
	"testing"

	"github.com/akitasoftware/akita-libs/akinet"
)

func TestClassifyHTTPDirection(t *testing.T) {
	hint := NewDirectionHint(
		[]net.IP{net.ParseIP("10.0.0.5").To4(), net.ParseIP("127.0.0.1").To4()},
		[]uint16{1337},
	)

	cases := []struct {
		name     string
		content  akinet.ParsedNetworkContent
		src, dst string
		sp, dp   int
		want     akinet.NetTrafficDirection
	}{
		{
			name:    "inbound request to app port",
			content: akinet.HTTPRequest{},
			src:     "10.0.0.9", dst: "10.0.0.5", sp: 40000, dp: 1337,
			want: akinet.DirectionInbound,
		},
		{
			name:    "inbound response from app port",
			content: akinet.HTTPResponse{},
			src:     "10.0.0.5", dst: "10.0.0.9", sp: 1337, dp: 40000,
			want: akinet.DirectionInbound,
		},
		{
			name:    "outbound request to remote",
			content: akinet.HTTPRequest{},
			src:     "10.0.0.5", dst: "10.0.0.9", sp: 50400, dp: 1337,
			want: akinet.DirectionOutbound,
		},
		{
			name:    "mesh outbound to envoy on lo",
			content: akinet.HTTPRequest{},
			src:     "10.0.0.5", dst: "127.0.0.1", sp: 50400, dp: 15001,
			want: akinet.DirectionOutbound,
		},
		{
			name:    "mesh inbound hairpin to app listen",
			content: akinet.HTTPRequest{},
			src:     "127.0.0.6", dst: "10.0.0.5", sp: 12345, dp: 1337,
			want: akinet.DirectionInbound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyHTTPDirection(tc.content, net.ParseIP(tc.src), net.ParseIP(tc.dst), tc.sp, tc.dp, hint)
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
