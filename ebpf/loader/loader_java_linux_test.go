// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package loader

import (
	"bytes"
	"os"
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

	t.Run("control frames are counted, not forwarded", func(t *testing.T) {
		before := counter(t, JavaCounterControlFrames)
		pwrite(t, javatls.Frame{Version: javatls.Version1, Op: javatls.OpClose, ConnID: 7}.Append(nil))
		expectNoEvent(t)
		if got := counter(t, JavaCounterControlFrames) - before; got != 1 {
			t.Errorf("control_frames grew by %d, want 1", got)
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

	if err := l.DisallowJavaNetns(netns); err != nil {
		t.Fatalf("DisallowJavaNetns: %v", err)
	}
	t.Run("netns removed again", func(t *testing.T) {
		pwrite(t, send)
		expectNoEvent(t)
	})
}
