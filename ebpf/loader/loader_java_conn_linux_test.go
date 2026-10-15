// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package loader

import (
	"fmt"
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
// connection's thread read from before its first RECV frame, or wrote to
// right after a SEND frame, with the tcp_recvmsg and tcp_sendmsg hooks
// attached by fexit and fentry, and by kprobes, or those of the
// connection's ADDRESS frame. Frames are written the way the Java agent
// writes them, from this process, with real TCP sockets.
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

// hasTrampolines reports whether the kernel supports BPF trampolines, which
// fexit needs: x86_64 5.5+, arm64 6.0+.
func hasTrampolines(t *testing.T) bool {
	t.Helper()
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		t.Fatal(err)
	}
	var major, minor int
	if _, err := fmt.Sscanf(unix.ByteSliceToString(u.Release[:]), "%d.%d", &major, &minor); err != nil {
		t.Fatalf("kernel release %q: %v", u.Release, err)
	}
	switch runtime.GOARCH {
	case "amd64":
		return major > 5 || major == 5 && minor >= 5
	case "arm64":
		return major >= 6
	}
	return false
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
	// A kernel with BPF trampolines attaches fexit: a fallback there hides a
	// bug, such as a tcp_recvmsg signature the loader does not know.
	if !kprobe && kind != "fexit" && hasTrampolines(t) {
		t.Fatalf("hook attached by %s on a kernel with BPF trampolines: %v", kind, l.JavaConnAddressesFallback())
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

	pwriteFlags := func(t *testing.T, op uint8, flags uint16, connID uint64, payload []byte) {
		t.Helper()
		frame := javatls.Frame{
			Version: javatls.Version1, Op: op, Flags: flags, ConnID: connID,
			TotalLen: uint32(len(payload)), Payload: payload,
		}.Append(nil)
		if _, err := unix.Pwrite(int(devNull.Fd()), frame, int64(javatls.Magic)); err != nil {
			t.Fatal(err)
		}
	}
	pwrite := func(t *testing.T, op uint8, connID uint64, payload string) {
		t.Helper()
		pwriteFlags(t, op, javatls.FlagRoleKnown, connID, []byte(payload))
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

	// A read that returned no bytes does not count: what the thread unwraps
	// next is not its socket's, and the read before it still ties (Tomcat
	// reads again, and gets EAGAIN, before unwrapping what an earlier read
	// buffered). A non-blocking read with nothing to read (EAGAIN), and one
	// at the end of the stream (0), each on a dup of the socket, outside Go's
	// poller.
	rawRead := func(t *testing.T, c net.Conn, nonblock bool) (int, error) {
		t.Helper()
		f, err := c.(*net.TCPConn).File()
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		// Fd puts the file in blocking mode: once, before setting the mode.
		fd := int(f.Fd())
		if nonblock {
			if err := syscall.SetNonblock(fd, true); err != nil {
				t.Fatal(err)
			}
		}
		return syscall.Read(fd, make([]byte, 1))
	}
	idle, _ := accept()
	ended, endedPeer := accept()
	_ = endedPeer.Close()
	const conn15, conn16 = 115, 116
	onThread(func() {
		readFrom(server1, client1)
		if n, err := rawRead(t, idle, true); err != syscall.EAGAIN {
			t.Fatalf("non-blocking read of an idle socket = %d, %v; want EAGAIN", n, err)
		}
		pwrite(t, javatls.OpRecv, conn15, "GET /buffered HTTP/1.1\r\n\r\n")
	})
	wantTuple(t, readEvent(t), server1)
	onThread(func() {
		readFrom(server1, client1)
		if n, err := rawRead(t, ended, false); n != 0 || err != nil {
			t.Fatalf("read at the end of the stream = %d, %v; want 0", n, err)
		}
		pwrite(t, javatls.OpRecv, conn16, "GET /buffered HTTP/1.1\r\n\r\n")
	})
	wantTuple(t, readEvent(t), server1)

	// A read whose return the kretprobe missed (more blocked readers on the
	// node than the kernel's limit of instances) leaves the socket being read
	// recorded: then the record is the read before it, maybe of another
	// socket, and nothing ties until a read returns. Simulated in both modes
	// by setting the field on this thread's record.
	const conn19 = 119
	onThread(func() {
		readFrom(server1, client1)
		key := uint64(os.Getpid())<<32 | uint64(unix.Gettid())
		var r javatlsThreadRead
		if err := l.java.objs.JavaThreadReads.Lookup(&key, &r); err != nil {
			t.Fatal(err)
		}
		r.ReadingSk = 1
		if err := l.java.objs.JavaThreadReads.Put(&key, &r); err != nil {
			t.Fatal(err)
		}
		pwrite(t, javatls.OpRecv, conn19, "GET / HTTP/1.1\r\n\r\n")
		// Only kprobes ever clear it: put the thread back for the rest.
		r.ReadingSk = 0
		if err := l.java.objs.JavaThreadReads.Put(&key, &r); err != nil {
			t.Fatal(err)
		}
	})
	if ev := readEvent(t); ev.Tuple.Family != events.ConnFamilyUnknown {
		t.Errorf("a connection tied while its thread's read return was missed: %+v", ev.Tuple)
	}
	// The read after a missed return (here one that gets EAGAIN) does not
	// bring back the record before the missed one either: with kprobes it
	// clears the mark the missed return left. (With fexit nothing clears the
	// mark, so the injected one alone stops the tie.)
	const conn22 = 122
	onThread(func() {
		readFrom(server1, client1)
		key := uint64(os.Getpid())<<32 | uint64(unix.Gettid())
		var r javatlsThreadRead
		if err := l.java.objs.JavaThreadReads.Lookup(&key, &r); err != nil {
			t.Fatal(err)
		}
		r.ReadingSk = 1
		if err := l.java.objs.JavaThreadReads.Put(&key, &r); err != nil {
			t.Fatal(err)
		}
		if n, err := rawRead(t, idle, true); err != syscall.EAGAIN {
			t.Fatalf("non-blocking read of an idle socket = %d, %v; want EAGAIN", n, err)
		}
		pwrite(t, javatls.OpRecv, conn22, "GET / HTTP/1.1\r\n\r\n")
		r.ReadingSk, r.TsNs = 0, 0
		if err := l.java.objs.JavaThreadReads.Put(&key, &r); err != nil {
			t.Fatal(err)
		}
	})
	if ev := readEvent(t); ev.Tuple.Family != events.ConnFamilyUnknown {
		t.Errorf("a connection tied to the read before a missed return: %+v", ev.Tuple)
	}

	// A client that reads on one thread and unwraps on another (the JDK's
	// HttpClient) still writes on the thread that wrapped: the SEND frame of a
	// connection not yet tied leaves it pending, and the thread's next socket
	// write ties it.
	const conn3, conn4 = 103, 104
	writeTo := func(c net.Conn, peer net.Conn) {
		if _, err := c.Write([]byte("y")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1)
		if _, err := peer.Read(buf); err != nil {
			t.Fatal(err)
		}
	}
	bound = counter(t, JavaCounterConnBound)
	onThread(func() {
		pwrite(t, javatls.OpSend, conn3, "")
		writeTo(server2, client2)
	})
	if got := counter(t, JavaCounterConnBound) - bound; got != 1 {
		t.Fatalf("conn_bound grew by %d, want 1", got)
	}
	pwrite(t, javatls.OpSend, conn3, "GET / HTTP/1.1\r\n\r\n")
	wantTuple(t, readEvent(t), server2)
	// Tied, a later SEND does not move it.
	onThread(func() {
		pwrite(t, javatls.OpSend, conn3, "more")
		writeTo(server1, client1)
	})
	wantTuple(t, readEvent(t), server2)
	// A write long after the SEND frame (the bytes were written by another
	// thread, and this one wrote something else) does not tie.
	onThread(func() {
		pwrite(t, javatls.OpSend, conn4, "")
		time.Sleep(20 * time.Millisecond)
		writeTo(server1, client1)
	})
	pwrite(t, javatls.OpSend, conn4, "GET / HTTP/1.1\r\n\r\n")
	if ev := readEvent(t); ev.Tuple.Family != events.ConnFamilyUnknown {
		t.Errorf("a stale pending connection got addresses %+v", ev.Tuple)
	}

	// A blocking read that waits long for its data still ties: the read
	// counts when it returns. A blocking socket (a dup through File, outside
	// Go's poller) so the receive itself waits in the kernel, as a JVM's
	// blocking SSLSocket read does.
	blockingRead := func(t *testing.T, c net.Conn) {
		t.Helper()
		f, err := c.(*net.TCPConn).File()
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		buf := make([]byte, 1)
		if _, err := syscall.Read(int(f.Fd()), buf); err != nil {
			t.Fatal(err)
		}
	}
	const conn5, conn6, conn9 = 105, 106, 109
	onThread(func() {
		go func() {
			time.Sleep(150 * time.Millisecond)
			_, _ = client2.Write([]byte("z"))
		}()
		start := time.Now()
		blockingRead(t, server2)
		if waited := time.Since(start); waited < 100*time.Millisecond {
			t.Fatalf("the read returned after %v, without waiting for the peer", waited)
		}
		pwrite(t, javatls.OpRecv, conn5, "GET /slow HTTP/1.1\r\n\r\n")
	})
	wantTuple(t, readEvent(t), server2)

	// Many threads of the node blocked in tcp_recvmsg at once do not use up
	// the kretprobe's instances, so a read still counts.
	others := make([]net.Conn, 0, 64)
	for i := 0; i < cap(others); i++ {
		server, client := accept()
		others = append(others, client)
		go func() {
			f, err := server.(*net.TCPConn).File()
			if err != nil {
				return
			}
			defer f.Close()
			_, _ = syscall.Read(int(f.Fd()), make([]byte, 1))
		}()
	}
	time.Sleep(200 * time.Millisecond) // until they block
	onThread(func() {
		readFrom(server1, client1)
		pwrite(t, javatls.OpRecv, conn9, "GET /busy HTTP/1.1\r\n\r\n")
	})
	wantTuple(t, readEvent(t), server1)
	for _, c := range others {
		_, _ = c.Write([]byte("w"))
	}

	// A dead process's connection with the same PID and connection id (a
	// reused PID) is not inherited: the key has the process's start time.
	stale := javatlsJavaConnKey{Tgid: uint32(os.Getpid()), StartNs: 1, ConnId: conn6}
	var staleTuple javatlsConnTuple
	staleTuple.Family = events.ConnFamilyInet
	staleTuple.LocalPort, staleTuple.RemotePort = 1, 2
	if err := l.java.objs.JavaConns.Put(&stale, &staleTuple); err != nil {
		t.Fatal(err)
	}
	onThread(func() {
		readFrom(server1, client1)
		pwrite(t, javatls.OpRecv, conn6, "GET / HTTP/1.1\r\n\r\n")
	})
	wantTuple(t, readEvent(t), server1)

	// A blocking socket's connection has the addresses of its ADDRESS frame,
	// with no read at all. Its frames (marked SOCKET) are never tied by the
	// thread's reads: a read of another socket before one neither moves the
	// connection nor counts as a mismatch, and one without its ADDRESS frame
	// (dropped) stays unknown.
	addressOf := func(c net.Conn) []byte {
		return javatls.Address{
			Local:  c.LocalAddr().(*net.TCPAddr).AddrPort(),
			Remote: c.RemoteAddr().(*net.TCPAddr).AddrPort(),
		}.Append(nil)
	}
	const socketFlags = javatls.FlagRoleKnown | javatls.FlagClientMode | javatls.FlagSocket
	const conn11, conn12 = 111, 112
	bound = counter(t, JavaCounterConnBound)
	onThread(func() { pwriteFlags(t, javatls.OpAddress, socketFlags, conn11, addressOf(server1)) })
	if got := counter(t, JavaCounterConnBound) - bound; got != 1 {
		t.Fatalf("conn_bound grew by %d at an ADDRESS frame, want 1", got)
	}
	mismatch = counter(t, JavaCounterConnMismatch)
	onThread(func() {
		readFrom(server2, client2)
		pwriteFlags(t, javatls.OpRecv, socketFlags, conn11, []byte("HTTP/1.1 200 OK\r\n\r\n"))
		readFrom(server2, client2)
		pwriteFlags(t, javatls.OpRecv, socketFlags, conn12, []byte("HTTP/1.1 200 OK\r\n\r\n"))
	})
	wantTuple(t, readEvent(t), server1)
	if ev := readEvent(t); ev.Tuple.Family != events.ConnFamilyUnknown {
		t.Errorf("a socket's frame was tied by its thread's read: %+v", ev.Tuple)
	}
	if got := counter(t, JavaCounterConnMismatch) - mismatch; got != 0 {
		t.Errorf("conn_mismatch grew by %d on a socket's frame, want 0", got)
	}

	// An ADDRESS frame replaces a tie the kernel made.
	pwriteFlags(t, javatls.OpAddress, socketFlags, conn9, addressOf(server2))
	pwrite(t, javatls.OpSend, conn9, "HTTP/1.1 200 OK\r\n\r\n")
	wantTuple(t, readEvent(t), server2)

	// A malformed ADDRESS frame is rejected and ties nothing.
	const conn13 = 113
	malformed := counter(t, JavaCounterMalformed)
	badFamily := addressOf(server1)
	badFamily[0] = 7
	trailing := addressOf(server1)
	trailing[8+4] = 1 // a byte after the IPv4 local address
	pwriteFlags(t, javatls.OpAddress, socketFlags, conn13, addressOf(server1)[:javatls.AddressSize-1])
	pwriteFlags(t, javatls.OpAddress, socketFlags, conn13, badFamily)
	pwriteFlags(t, javatls.OpAddress, socketFlags, conn13, trailing)
	if got := counter(t, JavaCounterMalformed) - malformed; got != 3 {
		t.Errorf("malformed grew by %d for three malformed ADDRESS frames, want 3", got)
	}
	pwrite(t, javatls.OpSend, conn13, "HTTP/1.1 200 OK\r\n\r\n")
	if ev := readEvent(t); ev.Tuple.Family != events.ConnFamilyUnknown {
		t.Errorf("a malformed ADDRESS frame tied its connection: %+v", ev.Tuple)
	}

	// A CLOSE whose event is dropped (here, by the rate cap) still forgets
	// its connection, so a closed connection takes no room in java_conns.
	const conn10 = 110
	onThread(func() {
		readFrom(server1, client1)
		pwrite(t, javatls.OpRecv, conn10, "GET / HTTP/1.1\r\n\r\n")
	})
	wantTuple(t, readEvent(t), server1)
	if err := l.SetRateCapPerSec(1); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // a fresh window
	pwrite(t, javatls.OpSend, conn10, "takes the only token")
	readEvent(t)
	pwrite(t, javatls.OpClose, conn10, "")
	// An ADDRESS frame takes a token too: over the cap, it ties nothing.
	const conn14 = 114
	pwriteFlags(t, javatls.OpAddress, socketFlags, conn14, addressOf(server1))
	var k javatlsJavaConnKey
	var v javatlsConnTuple
	for it := l.java.objs.JavaConns.Iterate(); it.Next(&k, &v); {
		if k.ConnId == conn10 && k.Tgid == uint32(os.Getpid()) {
			t.Error("a rate-capped CLOSE left its connection tied")
		}
		if k.ConnId == conn14 && k.Tgid == uint32(os.Getpid()) {
			t.Error("a rate-capped ADDRESS frame tied its connection")
		}
	}
	if err := l.SetRateCapPerSec(0); err != nil {
		t.Fatal(err)
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
