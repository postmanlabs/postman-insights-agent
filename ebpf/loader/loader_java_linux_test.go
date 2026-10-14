// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package loader

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
	"github.com/postmanlabs/postman-insights-agent/ebpf/javatls"
)

// TestJavaTLSFrames loads the Java TLS programs and writes frames from this
// process the way the Java agent does, with both syscalls the JVM can use:
// pwrite64 (glibc) and pwritev2 (musl). It checks what reaches the ring buffer
// and the counters.
//
// Requires root (CAP_BPF + CAP_PERFMON) and tracefs; skipped otherwise.
func TestJavaTLSFrames(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF + CAP_PERFMON)")
	}

	const captureCap = 64
	l, err := Load(Config{
		MaxCaptureBytes:           captureCap,
		EnableJava:                true,
		EnforceJavaNetnsAllowlist: true,
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer l.Close()
	if !l.JavaEnabled() {
		t.Fatalf("Java TLS programs did not load: %v", l.JavaError())
	}

	rd, err := ringbuf.NewReader(l.EventsMap())
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	devNull, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	fd := int(devNull.Fd())

	pwrite := func(t *testing.T, frame []byte) {
		t.Helper()
		if _, err := unix.Pwrite(fd, frame, int64(javatls.Magic)); err != nil {
			t.Fatalf("pwrite64: %v", err)
		}
	}
	pwritev2 := func(t *testing.T, frame []byte) {
		t.Helper()
		if _, err := unix.Pwritev2(fd, [][]byte{frame}, int64(javatls.Magic), unix.RWF_NOAPPEND); err != nil {
			t.Fatalf("pwritev2: %v", err)
		}
	}
	readEvent := func(t *testing.T) *events.SSLEvent {
		t.Helper()
		rd.SetDeadline(time.Now().Add(2 * time.Second))
		rec, err := rd.Read()
		if err != nil {
			t.Fatalf("ring buffer read: %v", err)
		}
		ev, err := events.Decode(rec.RawSample)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		return ev
	}
	expectNoEvent := func(t *testing.T) {
		t.Helper()
		rd.SetDeadline(time.Now().Add(200 * time.Millisecond))
		if rec, err := rd.Read(); err == nil {
			t.Fatalf("unexpected event of %d bytes", len(rec.RawSample))
		}
	}
	counter := func(t *testing.T, idx uint32) uint64 {
		t.Helper()
		v, err := l.ReadJavaCounter(idx)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}

	var st syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/net", &st); err != nil {
		t.Fatal(err)
	}
	netns := st.Ino

	request := []byte("GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n")
	send := javatls.Frame{
		Version:  javatls.Version1,
		Op:       javatls.OpSend,
		Flags:    javatls.FlagRoleKnown | javatls.FlagClientMode,
		ConnID:   7,
		TotalLen: uint32(len(request)),
		Payload:  request,
	}.Append(nil)

	t.Run("netns not allowed", func(t *testing.T) {
		before := counter(t, JavaCounterNetnsRejected)
		pwrite(t, send)
		expectNoEvent(t)
		if got := counter(t, JavaCounterNetnsRejected) - before; got != 1 {
			t.Errorf("netns_rejected grew by %d, want 1", got)
		}
	})

	if err := l.AllowJavaNetns(netns); err != nil {
		t.Fatalf("AllowJavaNetns: %v", err)
	}

	t.Run("pwrite64 send", func(t *testing.T) {
		pwrite(t, send)
		ev := readEvent(t)
		if ev.SSLCtx != javatls.SSLCtx(7) || ev.Direction != events.DirEgress || ev.FD != -1 ||
			uint64(ev.NetNS) != netns || ev.LenTotal != uint32(len(request)) ||
			ev.LenCaptured != uint32(len(request)) || !bytes.Equal(ev.Bytes(), request) {
			t.Errorf("event = ctx %#x dir %d fd %d netns %d total %d captured %d payload %q",
				ev.SSLCtx, ev.Direction, ev.FD, ev.NetNS, ev.LenTotal, ev.LenCaptured, ev.Bytes())
		}
	})

	t.Run("pwritev2 recv truncated by the kernel cap", func(t *testing.T) {
		body := bytes.Repeat([]byte("x"), 100)
		pwritev2(t, javatls.Frame{
			Version:  javatls.Version1,
			Op:       javatls.OpRecv,
			ConnID:   8,
			TotalLen: 4096,
			Payload:  body,
		}.Append(nil))
		ev := readEvent(t)
		if ev.SSLCtx != javatls.SSLCtx(8) || ev.Direction != events.DirIngress ||
			ev.LenTotal != 4096 || ev.LenCaptured != captureCap || !bytes.Equal(ev.Bytes(), body[:captureCap]) {
			t.Errorf("event = ctx %#x dir %d total %d captured %d", ev.SSLCtx, ev.Direction, ev.LenTotal, ev.LenCaptured)
		}
	})

	t.Run("malformed frames are dropped", func(t *testing.T) {
		before := counter(t, JavaCounterMalformed)
		bad := append([]byte(nil), send...)
		bad[0] = 2 // version
		pwrite(t, bad)
		pwrite(t, send[:len(send)-1]) // payload_len no longer matches the write
		pwrite(t, send[:javatls.HeaderSize-1])
		expectNoEvent(t)
		if got := counter(t, JavaCounterMalformed) - before; got != 3 {
			t.Errorf("malformed grew by %d, want 3", got)
		}
	})

	t.Run("control frames become control events", func(t *testing.T) {
		before := counter(t, JavaCounterControlFrames)
		status := []byte("agent_version=1.0.0\nstate=active\n")
		pwrite(t, javatls.Frame{Version: javatls.Version1, Op: javatls.OpHeartbeat,
			TotalLen: uint32(len(status)), Payload: status}.Append(nil))
		pwrite(t, javatls.Frame{Version: javatls.Version1, Op: javatls.OpClose, ConnID: 7}.Append(nil))

		rd.SetDeadline(time.Now().Add(2 * time.Second))
		rec, err := rd.Read()
		if err != nil {
			t.Fatal(err)
		}
		// sizeof(struct control_event), not a 16 KiB ssl_event.
		if n := len(rec.RawSample); n != 1072 {
			t.Errorf("heartbeat record of %d bytes, want 1072", n)
		}
		hb, err := events.Decode(rec.RawSample)
		if err != nil {
			t.Fatal(err)
		}
		if hb.Kind != events.KindJavaHeartbeat || uint64(hb.NetNS) != netns || !bytes.Equal(hb.Bytes(), status) {
			t.Errorf("heartbeat = kind %d netns %d payload %q", hb.Kind, hb.NetNS, hb.Bytes())
		}
		closed := readEvent(t)
		if closed.Kind != events.KindJavaClose || closed.SSLCtx != javatls.SSLCtx(7) || closed.LenCaptured != 0 {
			t.Errorf("close = kind %d ctx %#x captured %d", closed.Kind, closed.SSLCtx, closed.LenCaptured)
		}
		if got := counter(t, JavaCounterControlFrames) - before; got != 2 {
			t.Errorf("control_frames grew by %d, want 2", got)
		}
	})

	t.Run("data events are of kind data", func(t *testing.T) {
		pwrite(t, send)
		if ev := readEvent(t); ev.Kind != events.KindData {
			t.Errorf("kind %d", ev.Kind)
		}
	})

	t.Run("ordinary positional writes are ignored", func(t *testing.T) {
		before := counter(t, JavaCounterFramesSeen)
		if _, err := unix.Pwrite(fd, send, 0); err != nil {
			t.Fatal(err)
		}
		expectNoEvent(t)
		if got := counter(t, JavaCounterFramesSeen) - before; got != 0 {
			t.Errorf("frames_seen grew by %d, want 0", got)
		}
	})

	t.Run("rate cap applies to Java senders and refills every second", func(t *testing.T) {
		if err := l.SetRateCapPerSec(2); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.SetRateCapPerSec(0) }()
		drain := func() int {
			n := 0
			for {
				rd.SetDeadline(time.Now().Add(200 * time.Millisecond))
				if _, err := rd.Read(); err != nil {
					return n
				}
				n++
			}
		}
		before := counter(t, JavaCounterRateCapped)
		for i := 0; i < 5; i++ {
			pwrite(t, send)
		}
		if got := drain(); got != 2 {
			t.Errorf("%d events passed a cap of 2/s, want 2", got)
		}
		if got := counter(t, JavaCounterRateCapped) - before; got != 3 {
			t.Errorf("rate_capped grew by %d, want 3", got)
		}
		time.Sleep(1100 * time.Millisecond)
		pwrite(t, send)
		if got := drain(); got != 1 {
			t.Errorf("%d events after the window refilled, want 1", got)
		}
	})

	t.Run("rate cap applies to CLOSE, not HEARTBEAT", func(t *testing.T) {
		if err := l.SetRateCapPerSec(1); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.SetRateCapPerSec(0) }()
		time.Sleep(1100 * time.Millisecond) // a fresh window
		pwrite(t, send)                     // takes the only token
		closeFrame := javatls.Frame{Version: javatls.Version1, Op: javatls.OpClose, ConnID: 7}.Append(nil)
		pwrite(t, closeFrame)
		hb := javatls.Frame{Version: javatls.Version1, Op: javatls.OpHeartbeat}.Append(nil)
		pwrite(t, hb)
		if ev := readEvent(t); ev.Kind != events.KindData {
			t.Fatalf("first event kind %d, want data", ev.Kind)
		}
		if ev := readEvent(t); ev.Kind != events.KindJavaHeartbeat {
			t.Fatalf("second event kind %d, want the heartbeat (the close was capped)", ev.Kind)
		}
		expectNoEvent(t)
	})

	t.Run("heartbeats are limited per process", func(t *testing.T) {
		python, err := exec.LookPath("python3")
		if err != nil {
			t.Skip("needs python3, to write heartbeats from a fresh process")
		}
		before := counter(t, JavaCounterHeartbeatLimited)
		// From a process of its own, so this test's earlier heartbeats do not
		// count: three per 30 s pass, the fourth is dropped.
		hb := javatls.Frame{Version: javatls.Version1, Op: javatls.OpHeartbeat}.Append(nil)
		script := "import os; fd = os.open('/dev/null', os.O_WRONLY)\nfor _ in range(4): os.pwrite(fd, bytes.fromhex('" +
			hex.EncodeToString(hb) + "'), " + strconv.FormatUint(uint64(javatls.Magic), 10) + ")"
		if b, err := exec.Command(python, "-c", script).CombinedOutput(); err != nil {
			t.Fatalf("python: %v\n%s", err, b)
		}
		for i := 0; i < 3; i++ {
			if ev := readEvent(t); ev.Kind != events.KindJavaHeartbeat {
				t.Fatalf("event %d kind %d, want a heartbeat", i, ev.Kind)
			}
		}
		expectNoEvent(t)
		if got := counter(t, JavaCounterHeartbeatLimited) - before; got != 1 {
			t.Errorf("heartbeat_limited grew by %d, want 1", got)
		}
	})

	if err := l.DisallowJavaNetns(netns); err != nil {
		t.Fatalf("DisallowJavaNetns: %v", err)
	}
	t.Run("netns removed again", func(t *testing.T) {
		pwrite(t, send)
		expectNoEvent(t)
	})
}
