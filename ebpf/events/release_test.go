// SPDX-License-Identifier: Apache-2.0

package events

import (
	"fmt"
	"runtime"
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

// A flow forgotten by GC mid-body (libssl has no close event) must give its
// pool chunks back, or later responses on other flows lose their bodies.
func TestAdapter_GCForgetsFlowMidBody_NextResponseKeepsBody(t *testing.T) {
	pool, err := buffer_pool.MakeBufferPool(4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	fs := akinet.TCPParserFactorySelector{akihttp.NewHTTPRequestParserFactory(pool), akihttp.NewHTTPResponseParserFactory(pool)}
	out := make(chan akinet.ParsedNetworkTraffic, 8)
	a := NewAdapter(fs, out)

	feed(t, a, 4848, 0xA, DirEgress, []byte("HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\npartia"))
	gcAt := time.Unix(0, 0).Add(time.Hour)
	if n := a.GC(gcAt, 30*time.Second); n != 1 {
		t.Fatalf("GC forgot %d flows, want 1", n)
	}
	for len(out) > 0 {
		m := <-out
		if !m.FinalPacketTime.Before(gcAt.Add(-30 * time.Second)) {
			t.Errorf("FinalPacketTime %v is the GC time, want the last packet's time", m.FinalPacketTime)
		}
		ReleaseBuffers(m.Content)
	}

	feed(t, a, 4848, 0xB, DirEgress, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	select {
	case m := <-out:
		if n := m.Content.(akinet.HTTPResponse).Body.Len(); n != 2 {
			t.Fatalf("next response body length %d, want 2: the forgotten flow kept the pool's only chunk", n)
		}
	case <-time.After(time.Second):
		t.Fatal("next response not emitted")
	}
}

// Close must end a parser left mid-body, whose goroutine would otherwise
// block on its pipe and hold its pool chunks for the life of the process.
func TestAdapter_CloseWithFlowMidBody_ParserGoroutineEnds(t *testing.T) {
	a, _ := newTestAdapter(t)
	before := runtime.NumGoroutine()
	feed(t, a, 4848, 0xA, DirEgress, []byte("HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\npartia"))
	if runtime.NumGoroutine() <= before {
		t.Fatal("no parser goroutine started")
	}
	a.Close()
	for range 50 {
		if runtime.NumGoroutine() <= before {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("goroutines %d after Close, want <= %d", runtime.NumGoroutine(), before)
}
