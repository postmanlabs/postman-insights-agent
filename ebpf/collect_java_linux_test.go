// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package ebpf

import (
	"context"
	"encoding/hex"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"

	"github.com/postmanlabs/postman-insights-agent/ebpf/discovery"
	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
	"github.com/postmanlabs/postman-insights-agent/ebpf/javatls"
	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
	"github.com/postmanlabs/postman-insights-agent/ebpf/uprobes"
)

// TestCollectJavaOwnNetnsOnly: standalone Collect (apidump outside the
// DaemonSet, such as a sidecar with hostPID) accepts Java frames only from
// its own network namespace, never from other pods on the node.
func TestCollectJavaOwnNetnsOnly(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF + CAP_PERFMON)")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("needs python3, to write a frame from another netns")
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("needs unshare")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan akinet.ParsedNetworkTraffic, 16)
	ldr := make(chan *loader.Loader, 1)
	args := Defaults()
	args.EnableJava = true
	args.DisableThermostat = true
	args.FactorySelector = httpSelector(t)
	args.Out = out
	args.Discovery = make(chan discovery.Target)
	args.HookLoader = func(l *loader.Loader, _ *Thermostat, _ *uprobes.Manager, _ *events.Adapter) { ldr <- l }
	done := make(chan error, 1)
	go func() { done <- Collect(ctx, args) }()
	var l *loader.Loader
	select {
	case l = <-ldr:
	case err := <-done:
		t.Fatalf("Collect: %v", err)
	}
	if !l.JavaEnabled() {
		t.Fatalf("Java TLS programs did not load: %v", l.JavaError())
	}

	// From this process's netns: captured.
	writeJavaFrame(t, javatls.OpRecv, "GET /own HTTP/1.1\r\nHost: a\r\n\r\n")
	select {
	case pnt := <-out:
		if req, ok := pnt.Content.(akinet.HTTPRequest); !ok || req.URL.Path != "/own" {
			t.Fatalf("got %+v", pnt.Content)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a frame from the agent's own netns was not captured")
	}

	// From another netns: rejected.
	rejected := func() uint64 {
		v, err := l.ReadJavaCounter(loader.JavaCounterNetnsRejected)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	before := rejected()
	payload := "GET /other HTTP/1.1\r\nHost: b\r\n\r\n"
	frame := javatls.Frame{
		Version: javatls.Version1, Op: javatls.OpRecv, Flags: javatls.FlagRoleKnown,
		ConnID: 42, TotalLen: uint32(len(payload)), Payload: []byte(payload),
	}.Append(nil)
	script := "import os; fd = os.open('/dev/null', os.O_WRONLY); os.pwrite(fd, bytes.fromhex('" +
		hex.EncodeToString(frame) + "'), " + strconv.FormatUint(uint64(javatls.Magic), 10) + ")"
	if b, err := exec.Command(unshare, "--net", python, "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("write from another netns: %v\n%s", err, b)
	}
	deadline := time.Now().Add(3 * time.Second)
	for rejected() == before {
		if time.Now().After(deadline) {
			t.Fatal("a frame from another netns was not rejected")
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case pnt := <-out:
		t.Fatalf("captured a frame from another netns: %+v", pnt.Content)
	case <-time.After(200 * time.Millisecond):
	}
}
