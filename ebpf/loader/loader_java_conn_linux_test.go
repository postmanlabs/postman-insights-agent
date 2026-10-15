// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package loader

import (
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
	"github.com/postmanlabs/postman-insights-agent/ebpf/javatls"
)

// TestJavaConnAddresses: Java events carry the addresses of the socket their
// connection's thread read from before its first RECV frame, with the
// tcp_recvmsg hook attached by fentry and by kprobe. Frames are written the
// way the Java agent writes them, from this process, with real TCP sockets.
//
// Requires root (CAP_BPF + CAP_PERFMON) and tracefs; skipped otherwise.
func TestJavaConnAddresses(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF + CAP_PERFMON)")
	}
	for _, tc := range []struct {
		name   string
		kprobe bool
	}{
		{"auto", false},
		{"kprobe", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testJavaConnAddresses(t, tc.kprobe)
		})
	}
}

func testJavaConnAddresses(t *testing.T, kprobe bool) {
	l, err := Load(Config{
		MaxCaptureBytes:           64,
		EnableJava:                true,
		EnforceJavaNetnsAllowlist: true,
		javaReadHookKprobe:        kprobe,
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer l.Close()
	if !l.JavaEnabled() {
		t.Fatalf("Java TLS programs did not load: %v", l.JavaError())
	}
	kind, err := l.JavaConnAddresses()
	if err != nil {
		t.Fatalf("tcp_recvmsg hook not attached: %v", err)
	}
	if kprobe && kind != "kprobe" {
		t.Fatalf("hook attached by %s, want kprobe", kind)
	}
	t.Logf("tcp_recvmsg hook attached by %s", kind)

	var st syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/net", &st); err != nil {
		t.Fatal(err)
	}
	if err := l.AllowJavaNetns(st.Ino); err != nil {
		t.Fatal(err)
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

	pwrite := func(t *testing.T, op uint8, connID uint64, payload string) {
		t.Helper()
		frame := javatls.Frame{
			Version: javatls.Version1, Op: op, Flags: javatls.FlagRoleKnown, ConnID: connID,
			TotalLen: uint32(len(payload)), Payload: []byte(payload),
		}.Append(nil)
		if _, err := unix.Pwrite(int(devNull.Fd()), frame, int64(javatls.Magic)); err != nil {
			t.Fatal(err)
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
			t.Fatal(err)
		}
		return ev
	}
	counter := func(t *testing.T, idx uint32) uint64 {
		t.Helper()
		v, err := l.ReadJavaCounter(idx)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	wantTuple := func(t *testing.T, ev *events.SSLEvent, c net.Conn) {
		t.Helper()
		info, ok := ev.Tuple.SocketInfo()
		local, remote := c.LocalAddr().(*net.TCPAddr), c.RemoteAddr().(*net.TCPAddr)
		if !ok || !info.LocalIP.Equal(local.IP) || info.LocalPort != local.Port ||
			!info.RemoteIP.Equal(remote.IP) || info.RemotePort != remote.Port {
			t.Fatalf("event addresses %+v (known %v), want %s -> %s", info, ok, local, remote)
		}
	}

	// From now on this process counts as one that sends frames.
	pwrite(t, javatls.OpHeartbeat, 0, "state=active\n")
	if ev := readEvent(t); ev.Kind != events.KindJavaHeartbeat {
		t.Fatalf("kind %d", ev.Kind)
	}

	// Two server-side connections, as a JVM serving two clients has.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accept := func() (server, client net.Conn) {
		client, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		server, err = ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
		return server, client
	}
	server1, client1 := accept()
	server2, client2 := accept()

	// What the JVM's server thread does: read the socket, then unwrap what
	// it read. The thread is locked so the read and the frame share it.
	onThread := func(f func()) {
		done := make(chan struct{})
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			defer close(done)
			f()
		}()
		<-done
	}
	readFrom := func(c net.Conn, peer net.Conn) {
		if _, err := peer.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1)
		if _, err := c.Read(buf); err != nil {
			t.Fatal(err)
		}
	}
	const conn1, conn2 = 101, 102

	bound := counter(t, JavaCounterConnBound)
	// The handshake: an empty RECV frame after the socket read ties the
	// connection, and sends nothing.
	onThread(func() {
		readFrom(server1, client1)
		pwrite(t, javatls.OpRecv, conn1, "")
	})
	if got := counter(t, JavaCounterConnBound) - bound; got != 1 {
		t.Fatalf("conn_bound grew by %d, want 1", got)
	}
	// The request and the response carry the addresses, the response sent
	// from a thread that read nothing.
	onThread(func() {
		readFrom(server1, client1)
		pwrite(t, javatls.OpRecv, conn1, "GET / HTTP/1.1\r\n\r\n")
	})
	wantTuple(t, readEvent(t), server1)
	pwrite(t, javatls.OpSend, conn1, "HTTP/1.1 200 OK\r\n\r\n")
	wantTuple(t, readEvent(t), server1)

	// A thread that read another socket before a RECV frame of conn1 does
	// not move conn1: it is counted.
	mismatch := counter(t, JavaCounterConnMismatch)
	onThread(func() {
		readFrom(server2, client2)
		pwrite(t, javatls.OpRecv, conn1, "GET /2 HTTP/1.1\r\n\r\n")
	})
	wantTuple(t, readEvent(t), server1)
	if got := counter(t, JavaCounterConnMismatch) - mismatch; got != 1 {
		t.Errorf("conn_mismatch grew by %d, want 1", got)
	}

	// A connection whose thread read nothing stays unknown, rather than
	// taking a stale or another thread's socket.
	// (Past THREAD_READ_MAX_AGE_NS, in case the thread is one that read.)
	time.Sleep(60 * time.Millisecond)
	unbound := counter(t, JavaCounterConnUnbound)
	onThread(func() { pwrite(t, javatls.OpRecv, conn2, "GET / HTTP/1.1\r\n\r\n") })
	if ev := readEvent(t); ev.Tuple.Family != events.ConnFamilyUnknown {
		t.Errorf("an unread connection got addresses %+v", ev.Tuple)
	}
	if got := counter(t, JavaCounterConnUnbound) - unbound; got != 1 {
		t.Errorf("conn_unbound grew by %d, want 1", got)
	}

	// CLOSE carries the addresses and forgets the connection.
	pwrite(t, javatls.OpClose, conn1, "")
	ev := readEvent(t)
	if ev.Kind != events.KindJavaClose {
		t.Fatalf("kind %d, want CLOSE", ev.Kind)
	}
	wantTuple(t, ev, server1)
	pwrite(t, javatls.OpSend, conn1, "late")
	if ev := readEvent(t); ev.Tuple.Family != events.ConnFamilyUnknown {
		t.Errorf("a closed connection still has addresses %+v", ev.Tuple)
	}
}
