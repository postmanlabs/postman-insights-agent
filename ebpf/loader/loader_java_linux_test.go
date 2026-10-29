// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package loader

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
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
		if _, err := unix.Pwritev2(fd, [][]byte{frame}, int64(javatls.Magic), 0); err != nil {
			t.Fatalf("pwritev2: %v", err)
		}
	}
	// muslPwrite writes the way musl's pwrite() does: pwritev2 with
	// RWF_NOAPPEND, then pwrite64 if the kernel rejects the flag (before 6.9).
	muslPwrite := func(t *testing.T, frame []byte) {
		t.Helper()
		_, err := unix.Pwritev2(fd, [][]byte{frame}, int64(javatls.Magic), unix.RWF_NOAPPEND)
		if errors.Is(err, unix.EOPNOTSUPP) {
			_, err = unix.Pwrite(fd, frame, int64(javatls.Magic))
		}
		if err != nil {
			t.Fatalf("musl pwrite: %v", err)
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

	// The counters are the kernel's, for every process: JVMs elsewhere on the
	// machine (a kind cluster on the same VM) send frames too, which are
	// rejected for their netns. So frames_seen and netns_rejected are never
	// asserted exactly; the counters past the netns check only count frames
	// from this process's netns.
	t.Run("netns not allowed", func(t *testing.T) {
		before := counter(t, JavaCounterNetnsRejected)
		pwrite(t, send)
		expectNoEvent(t)
		if got := counter(t, JavaCounterNetnsRejected) - before; got < 1 {
			t.Errorf("netns_rejected grew by %d, want at least 1", got)
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

	// On every kernel: one write with RWF_NOAPPEND where it is supported,
	// else a rejected one and a pwrite64, which must not read the frame twice.
	t.Run("musl pwrite gives one event", func(t *testing.T) {
		muslPwrite(t, send)
		if ev := readEvent(t); ev.SSLCtx != javatls.SSLCtx(7) || !bytes.Equal(ev.Bytes(), request) {
			t.Errorf("event = ctx %#x payload %q", ev.SSLCtx, ev.Bytes())
		}
		expectNoEvent(t)
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

	// A later agent may use them within version 1 (java_frame.h).
	t.Run("reserved bytes and undefined flag bits are ignored", func(t *testing.T) {
		later := append([]byte(nil), send...)
		for i := 16; i < 36; i++ { // the reserved bytes
			later[i] = byte(i)
		}
		binary.LittleEndian.PutUint16(later[2:], javatls.FlagRoleKnown|javatls.FlagClientMode|0x4|0x8000)
		if _, err := javatls.Parse(later); err != nil {
			t.Fatalf("Parse: %v", err)
		}
		pwrite(t, later)
		if ev := readEvent(t); ev.SSLCtx != javatls.SSLCtx(7) || !bytes.Equal(ev.Bytes(), request) {
			t.Errorf("event = ctx %#x payload %q", ev.SSLCtx, ev.Bytes())
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
		if n := len(rec.RawSample); n != 1112 {
			t.Errorf("heartbeat record of %d bytes, want 1112", n)
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
		// Not a frame: never parsed (frames that fail parsing are counted as
		// malformed, only for this process's netns, so other JVMs on the
		// machine cannot disturb the count) and never an event.
		malformed := counter(t, JavaCounterMalformed)
		if _, err := unix.Pwrite(fd, send, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := unix.Pwrite(fd, []byte("not a frame at all"), int64(javatls.Magic)+1); err != nil {
			t.Fatal(err)
		}
		expectNoEvent(t)
		if got := counter(t, JavaCounterMalformed) - malformed; got != 0 {
			t.Errorf("malformed grew by %d, want 0", got)
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

	// Many threads of one process hitting an empty bucket at once: the
	// limit holds. An unsigned count wrapped around to "full" here, letting
	// everything through.
	hammer := func(t *testing.T, frame []byte, threads, each int) int {
		t.Helper()
		python, err := exec.LookPath("python3")
		if err != nil {
			t.Skip("needs python3, to write frames from a fresh process")
		}
		script := "import os, threading\nfd = os.open('/dev/null', os.O_WRONLY)\nf = bytes.fromhex('" +
			hex.EncodeToString(frame) + "')\ndef w():\n    for _ in range(" + strconv.Itoa(each) +
			"): os.pwrite(fd, f, " + strconv.FormatUint(uint64(javatls.Magic), 10) + ")\n" +
			"ts = [threading.Thread(target=w) for _ in range(" + strconv.Itoa(threads) + ")]\n" +
			"[x.start() for x in ts]\n[x.join() for x in ts]\n"
		if b, err := exec.Command(python, "-c", script).CombinedOutput(); err != nil {
			t.Fatalf("python: %v\n%s", err, b)
		}
		n := 0
		for {
			rd.SetDeadline(time.Now().Add(300 * time.Millisecond))
			if _, err := rd.Read(); err != nil {
				return n
			}
			n++
		}
	}
	t.Run("heartbeat limit holds under concurrent senders", func(t *testing.T) {
		hb := javatls.Frame{Version: javatls.Version1, Op: javatls.OpHeartbeat}.Append(nil)
		if n := hammer(t, hb, 8, 500); n != 3 {
			t.Errorf("%d heartbeats from 8 threads sending 500 each, want 3", n)
		}
	})
	t.Run("rate cap holds under concurrent senders", func(t *testing.T) {
		if err := l.SetRateCapPerSec(2); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.SetRateCapPerSec(0) }()
		start := time.Now()
		n := hammer(t, send, 8, 500)
		// 2 per one-second window; a new window can start on several CPUs
		// at once, each with a full bucket.
		windows := int(time.Since(start)/time.Second) + 1
		if limit := windows * (2 + runtime.NumCPU()); n > limit {
			t.Errorf("%d events from 8 threads sending 500 each in %d windows, want at most %d", n, windows, limit)
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

// TestJavaTLSNoAppendRejected loads the Java TLS programs as on a kernel
// before 6.9, which rejects pwritev2's RWF_NOAPPEND: such a pwritev2 is
// skipped, since musl writes the frame again with pwrite64, while pwritev2
// without the flag and pwrite64 are read.
func TestJavaTLSNoAppendRejected(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF + CAP_PERFMON)")
	}
	l, err := Load(Config{
		MaxCaptureBytes:           64,
		EnableJava:                true,
		EnforceJavaNetnsAllowlist: true,
		javaNoAppendRejected:      true,
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

	var st syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/net", &st); err != nil {
		t.Fatal(err)
	}
	if err := l.AllowJavaNetns(st.Ino); err != nil {
		t.Fatalf("AllowJavaNetns: %v", err)
	}
	defer l.DisallowJavaNetns(st.Ino)

	devNull, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	fd := int(devNull.Fd())

	frame := func(connID uint64) []byte {
		return javatls.Frame{Version: javatls.Version1, Op: javatls.OpSend, ConnID: connID,
			TotalLen: 5, Payload: []byte("hello")}.Append(nil)
	}
	// readConn returns the conn id of the next event, or 0 when there is none.
	readConn := func() uint64 {
		rd.SetDeadline(time.Now().Add(500 * time.Millisecond))
		rec, err := rd.Read()
		if err != nil {
			return 0
		}
		ev, err := events.Decode(rec.RawSample)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		return ev.SSLCtx &^ javatls.ConnIDTag
	}

	// The kernel this runs on may accept the flag; the program skips the call
	// either way.
	_, _ = unix.Pwritev2(fd, [][]byte{frame(1)}, int64(javatls.Magic), unix.RWF_NOAPPEND)
	if _, err := unix.Pwritev2(fd, [][]byte{frame(2)}, int64(javatls.Magic), 0); err != nil {
		t.Fatalf("pwritev2: %v", err)
	}
	if _, err := unix.Pwrite(fd, frame(3), int64(javatls.Magic)); err != nil {
		t.Fatalf("pwrite64: %v", err)
	}
	var got []uint64
	for id := readConn(); id != 0; id = readConn() {
		got = append(got, id)
	}
	if len(got) != 2 || got[0] != 2 || got[1] != 3 {
		t.Errorf("events for conn ids %v, want [2 3]", got)
	}
}

// pwritev2RejectsNoAppend matches the kernel: RWF_NOAPPEND is Linux 6.9+.
func TestPwritev2RejectsNoAppend(t *testing.T) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		t.Fatal(err)
	}
	release := unix.ByteSliceToString(u.Release[:])
	var major, minor int
	if _, err := fmt.Sscanf(release, "%d.%d", &major, &minor); err != nil {
		t.Fatalf("kernel release %q: %v", release, err)
	}
	want := major < 6 || major == 6 && minor < 9
	if got := pwritev2RejectsNoAppend(); got != want {
		t.Errorf("kernel %s: pwritev2RejectsNoAppend() = %v, want %v", release, got, want)
	}
}
