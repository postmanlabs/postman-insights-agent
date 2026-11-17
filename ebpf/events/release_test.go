// SPDX-License-Identifier: Apache-2.0

package events

import (
	"fmt"
	"testing"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	akihttp "github.com/akitasoftware/akita-libs/akinet/http"
	"github.com/akitasoftware/akita-libs/buffer_pool"
	"github.com/akitasoftware/akita-libs/memview"
)

func TestReleaseBuffers_MessageWithoutPoolBuffer_DoesNotPanic(t *testing.T) {
	ReleaseBuffers(akinet.HTTPRequest{Method: "GET", Body: memview.New([]byte("x"))})
	ReleaseBuffers(akinet.HTTPResponse{StatusCode: 200, Body: memview.New([]byte("x"))})
}

// One pool chunk, so it is used up by the first body unless released after each response.
func TestReleaseBuffers_OneChunkPool(t *testing.T) {
	hdr := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n")
	body := []byte(`{"status": "ok"}`)
	tests := []struct {
		name    string
		release bool
		want    []int // body length of each response
	}{
		{"not_released_bodies_after_first_are_empty", false, []int{16, 0, 0, 0, 0}},
		{"released_every_body_is_kept", true, []int{16, 16, 16, 16, 16}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool, err := buffer_pool.MakeBufferPool(4096, 4096)
			if err != nil {
				t.Fatal(err)
			}
			fs := akinet.TCPParserFactorySelector{akihttp.NewHTTPRequestParserFactory(pool), akihttp.NewHTTPResponseParserFactory(pool)}
			out := make(chan akinet.ParsedNetworkTraffic, 32)
			a := NewAdapter(fs, out)
			var got []int
			for range tt.want {
				feed(t, a, 4747, 0xC0DE, DirEgress, hdr)
				feed(t, a, 4747, 0xC0DE, DirEgress, body)
				select {
				case p := <-out:
					got = append(got, int(p.Content.(akinet.HTTPResponse).Body.Len()))
					if tt.release {
						ReleaseBuffers(p.Content)
					}
				case <-time.After(time.Second):
					t.Fatalf("response %d not emitted", len(got)+1)
				}
			}
			t.Logf("body lengths: %v", got)
			if fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Fatalf("body lengths %v, want %v", got, tt.want)
			}
		})
	}
}
