// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

import (
	"context"
	"os"
	"os/exec"
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
	"github.com/postmanlabs/postman-insights-agent/ebpf/uprobes"
)

// TestNodeCollectorJavaFrames runs the DaemonSet path end to end below the
// Java agent: frames written from a subscribed pod's netns (this process's)
// come out of the pod's subscription as parsed HTTP, with no socket fd, and
// frames stop being accepted once the subscription is cancelled.
//
// Requires root (CAP_BPF + CAP_PERFMON) and tracefs; skipped otherwise.
// javaTestCollector starts a NodeCollector with Java capture, as the
// DaemonSet does. hostNetns is cleared, because the tests run in the host's
// netns in the dev container (--network=host); tests that need it set it.
func javaTestCollector(t *testing.T) (*NodeCollector, context.Context) {
	t.Helper()
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
	t.Cleanup(func() { _ = nc.Close() })
	if !nc.Loader().JavaEnabled() {
		t.Fatalf("Java TLS programs did not load: %v", nc.Loader().JavaError())
	}
	nc.hostNetns = 0

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = nc.Run(ctx) }()
	return nc, ctx
}

func httpSelector(t *testing.T) akinet.TCPParserFactorySelector {
	t.Helper()
	pool, err := buffer_pool.MakeBufferPool(16*1024*1024, 4096)
	if err != nil {
		t.Fatal(err)
	}
	return akinet.TCPParserFactorySelector{
		akihttp.NewHTTPRequestParserFactory(pool),
		akihttp.NewHTTPResponseParserFactory(pool),
	}
}

func ownNetns(t *testing.T) uint64 {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/net", &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}

// writeJavaFrame writes one frame from this process, as the Java agent does.
func writeJavaFrame(t *testing.T, op uint8, payload string) {
	t.Helper()
	devNull, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
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

func javaCounter(t *testing.T, nc *NodeCollector, idx uint32) uint64 {
	t.Helper()
	v, err := nc.Loader().ReadJavaCounter(idx)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// expectRejected writes frames until the netns-rejected counter moves, or
// fails after a few seconds (cancellation cleanup runs asynchronously).
func expectRejected(t *testing.T, nc *NodeCollector) {
	t.Helper()
	before := javaCounter(t, nc, loader.JavaCounterNetnsRejected)
	deadline := time.Now().Add(3 * time.Second)
	for javaCounter(t, nc, loader.JavaCounterNetnsRejected) == before {
		if time.Now().After(deadline) {
			t.Fatal("frames still accepted")
		}
		writeJavaFrame(t, javatls.OpRecv, "GET /late HTTP/1.1\r\n\r\n")
		time.Sleep(20 * time.Millisecond)
	}
}

// TestNodeCollectorJavaFrames runs the DaemonSet path end to end below the
// Java agent: frames written from a subscribed pod's netns (this process's)
// come out of the pod's subscription as parsed HTTP, with no socket fd, and
// frames stop being accepted once the subscription is cancelled.
//
// Requires root (CAP_BPF + CAP_PERFMON) and tracefs; skipped otherwise.
func TestNodeCollectorJavaFrames(t *testing.T) {
	nc, ctx := javaTestCollector(t)
	out := make(chan akinet.ParsedNetworkTraffic, 16)
	unsubscribe, _ := nc.Subscribe(ctx, make(chan discovery.Target), httpSelector(t), out, "", ownNetns(t))

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

	writeJavaFrame(t, javatls.OpRecv, "GET /orders/7?expand=items HTTP/1.1\r\nHost: shop.internal\r\n\r\n")
	writeJavaFrame(t, javatls.OpSend, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"id\":\"7\"}\n")

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
	expectRejected(t, nc)
}

// TestNodeCollectorJavaRefusesHostNetns: hostNetwork pods share the node's
// netns with every host process, so it never identifies one pod.
func TestNodeCollectorJavaRefusesHostNetns(t *testing.T) {
	nc, ctx := javaTestCollector(t)
	nc.hostNetns = ownNetns(t)
	out := make(chan akinet.ParsedNetworkTraffic, 16)
	unsubscribe, _ := nc.Subscribe(ctx, make(chan discovery.Target), httpSelector(t), out, "", nc.hostNetns)
	defer unsubscribe()
	expectRejected(t, nc)
	select {
	case <-out:
		t.Fatal("traffic from the host netns was captured")
	default:
	}
}

// TestNodeCollectorJavaSharedNetns: with two subscriptions on one netns,
// whichever is cancelled first, the other's frames are still accepted by the
// kernel and still delivered to it as parsed HTTP.
func TestNodeCollectorJavaSharedNetns(t *testing.T) {
	nc, ctx := javaTestCollector(t)
	netns := ownNetns(t)
	sel := httpSelector(t)

	for _, firstLeaves := range []string{"older", "newer"} {
		t.Run(firstLeaves+" cancelled first", func(t *testing.T) {
			olderOut := make(chan akinet.ParsedNetworkTraffic, 16)
			newerOut := make(chan akinet.ParsedNetworkTraffic, 16)
			cancelOlder, _ := nc.Subscribe(ctx, make(chan discovery.Target), sel, olderOut, "", netns)
			cancelNewer, _ := nc.Subscribe(ctx, make(chan discovery.Target), sel, newerOut, "", netns)

			cancelFirst, cancelSecond, stayingOut := cancelOlder, cancelNewer, newerOut
			if firstLeaves == "newer" {
				cancelFirst, cancelSecond, stayingOut = cancelNewer, cancelOlder, olderOut
			}
			cancelFirst()
			time.Sleep(200 * time.Millisecond) // let the cancelled subscription's cleanup run

			writeJavaFrame(t, javatls.OpRecv, "GET /still-here HTTP/1.1\r\nHost: x\r\n\r\n")
			select {
			case pnt := <-stayingOut:
				req, ok := pnt.Content.(akinet.HTTPRequest)
				if !ok || req.URL.Path != "/still-here" {
					t.Fatalf("remaining subscription got %T %v", pnt.Content, pnt.Content)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the remaining subscription received nothing")
			}

			cancelSecond()
			expectRejected(t, nc)
		})
	}
}

// TestNodeCollectorJavaCleanupWhenDiscoveryCloses: discovery closes its channel
// when the capture context ends, which the subscription may see before the
// context; cleanup must still run.
func TestNodeCollectorJavaCleanupWhenDiscoveryCloses(t *testing.T) {
	nc, ctx := javaTestCollector(t)
	disco := make(chan discovery.Target)
	unsubscribe, _ := nc.Subscribe(ctx, disco, httpSelector(t), make(chan akinet.ParsedNetworkTraffic, 16), "", ownNetns(t))
	defer unsubscribe()
	close(disco)
	expectRejected(t, nc)
}

// TestNodeCollectorSharedPIDKeepsProbes: two subscriptions can share a PID
// (hostNetwork pods). The uprobes manager attaches once per PID, so the probes
// must stay attached until the last subscription using them leaves. Uses a
// Python process, which maps the system libssl.
func TestNodeCollectorSharedPIDKeepsProbes(t *testing.T) {
	nc, ctx := javaTestCollector(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("needs python3, to run a process that maps libssl")
	}
	cmd := exec.Command(python, "-c", "import ssl, time; time.sleep(60)")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	pid := uint32(cmd.Process.Pid)

	var lib *uprobes.LibSSLPath
	deadline := time.Now().Add(5 * time.Second)
	for lib == nil {
		if time.Now().After(deadline) {
			t.Fatal("python3 never mapped libssl")
		}
		lib, _ = uprobes.FindLibSSLAnyAt("/proc", pid)
		time.Sleep(20 * time.Millisecond)
	}
	target := discovery.Target{PID: pid, Lib: lib, Seen: time.Now()}

	sel := httpSelector(t)
	discoA, discoB := make(chan discovery.Target, 1), make(chan discovery.Target, 1)
	cancelA, _ := nc.Subscribe(ctx, discoA, sel, make(chan akinet.ParsedNetworkTraffic, 16), "", 0)
	cancelB, _ := nc.Subscribe(ctx, discoB, sel, make(chan akinet.ParsedNetworkTraffic, 16), "", 0)
	defer cancelB()

	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatal(what)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	routed := func() int {
		nc.mu.RLock()
		defer nc.mu.RUnlock()
		return len(nc.pidToSub[pid])
	}
	discoA <- target
	discoB <- target
	waitFor("both subscriptions never routed the PID", func() bool { return routed() == 2 })
	probes := nc.mgr.ProbeCount(pid)
	if probes == 0 {
		t.Fatal("no uprobes attached")
	}

	cancelA()
	waitFor("the cancelled subscription is still routed", func() bool { return routed() == 1 })
	if got := nc.mgr.ProbeCount(pid); got != probes {
		t.Fatalf("%d probes left after one of two subscriptions left, want %d", got, probes)
	}

	discoB <- discovery.Target{PID: pid, Removed: true, Seen: time.Now()}
	waitFor("probes still attached after the last subscription released the PID",
		func() bool { return nc.mgr.ProbeCount(pid) == 0 })
}
