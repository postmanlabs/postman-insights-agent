// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	akihttp "github.com/akitasoftware/akita-libs/akinet/http"
	"github.com/akitasoftware/akita-libs/buffer_pool"
	"golang.org/x/sys/unix"

	"github.com/postmanlabs/postman-insights-agent/ebpf/discovery"
	"github.com/postmanlabs/postman-insights-agent/ebpf/javatls"
	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
)

// TestNodeCollectorJavaFrames runs the DaemonSet path end to end below the
// Java agent: frames written from a subscribed pod's netns (this process's)
// come out of the pod's subscription as parsed HTTP, with no socket fd, and
// frames stop being accepted once the subscription is cancelled.
//
// Requires root (CAP_BPF + CAP_PERFMON) and tracefs; skipped otherwise.
func TestNodeCollectorJavaFrames(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF + CAP_PERFMON)")
	}

	nc, err := NewNodeCollector(NodeCollectorConfig{
		MaxCaptureBytes:   16384,
		DisableThermostat: true,
		EnableJava:        true,
	})
	if err != nil {
		t.Fatalf("NewNodeCollector: %v", err)
	}
	defer nc.Close()
	if !nc.Loader().JavaEnabled() {
		t.Fatalf("Java TLS programs did not load: %v", nc.Loader().JavaError())
	}

	ctx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	go func() { _ = nc.Run(ctx) }()

	pool, err := buffer_pool.MakeBufferPool(16*1024*1024, 4096)
	if err != nil {
		t.Fatal(err)
	}
	selector := akinet.TCPParserFactorySelector{
		akihttp.NewHTTPRequestParserFactory(pool),
		akihttp.NewHTTPResponseParserFactory(pool),
	}

	var st syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/net", &st); err != nil {
		t.Fatal(err)
	}
	out := make(chan akinet.ParsedNetworkTraffic, 16)
	disco := make(chan discovery.Target)
	unsubscribe, _ := nc.Subscribe(ctx, disco, selector, out, "", st.Ino)

	devNull, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	write := func(op uint8, payload string) {
		t.Helper()
		frame := javatls.Frame{
			Version:  javatls.Version1,
			Op:       op,
			Flags:    javatls.FlagRoleKnown, // server
			ConnID:   41,
			TotalLen: uint32(len(payload)),
			Payload:  []byte(payload),
		}.Append(nil)
		if _, err := unix.Pwrite(int(devNull.Fd()), frame, int64(javatls.Magic)); err != nil {
			t.Fatalf("pwrite: %v", err)
		}
	}
	next := func() akinet.ParsedNetworkTraffic {
		t.Helper()
		select {
		case pnt := <-out:
			return pnt
		case <-time.After(3 * time.Second):
			t.Fatal("no parsed traffic from the subscription")
			return akinet.ParsedNetworkTraffic{}
		}
	}

	write(javatls.OpRecv, "GET /orders/7?expand=items HTTP/1.1\r\nHost: shop.internal\r\n\r\n")
	write(javatls.OpSend, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"id\":\"7\"}\n")

	req, ok := next().Content.(akinet.HTTPRequest)
	if !ok {
		t.Fatalf("first message is not a request")
	}
	if req.Method != "GET" || req.URL.Path != "/orders/7" || req.URL.RawQuery != "expand=items" {
		t.Errorf("request = %s %v", req.Method, req.URL)
	}
	respPNT := next()
	resp, ok := respPNT.Content.(akinet.HTTPResponse)
	if !ok {
		t.Fatalf("second message is not a response")
	}
	if resp.StatusCode != 200 || resp.StreamID != req.StreamID || resp.Seq != req.Seq {
		t.Errorf("response status %d, pair (%v, %d), request pair (%v, %d)",
			resp.StatusCode, resp.StreamID, resp.Seq, req.StreamID, req.Seq)
	}
	if respPNT.Direction != akinet.DirectionInbound || respPNT.TransportSecurity != akinet.TransportSecurityTLS {
		t.Errorf("response direction %v, security %v", respPNT.Direction, respPNT.TransportSecurity)
	}

	// After the pod goes away its netns is no longer accepted.
	unsubscribe()
	rejected := func() uint64 {
		v, err := nc.Loader().ReadJavaCounter(loader.JavaCounterNetnsRejected)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	before := rejected()
	deadline := time.Now().Add(3 * time.Second)
	for rejected() == before {
		if time.Now().After(deadline) {
			t.Fatal("frames still accepted after the subscription was cancelled")
		}
		write(javatls.OpRecv, "GET /late HTTP/1.1\r\n\r\n")
		time.Sleep(20 * time.Millisecond)
	}
}
