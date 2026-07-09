// SPDX-License-Identifier: Apache-2.0

package events

import (
	"net"
	"os"
	"strconv"
	"testing"
	"time"
)

// TestResolverAgainstRealSocket opens a real TCP listener + outbound
// connection in the current process, finds the fd via /proc/self/fd, and
// verifies the resolver extracts the correct 4-tuple.
func TestResolverAgainstRealSocket(t *testing.T) {
	// Listen on a random port.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	// Dial to it. Keep both ends alive for the duration of the test.
	dialCh := make(chan net.Conn, 1)
	go func() {
		c, err := net.Dial("tcp4", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			t.Errorf("dial: %v", err)
			return
		}
		dialCh <- c
	}()
	srv, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer srv.Close()
	client := <-dialCh
	defer client.Close()

	// Extract a usable fd for `srv` via reflection-style file descriptor
	// retrieval. net.TCPConn supports SyscallConn → Control to give us the fd.
	srvFd, err := tcpFD(srv)
	if err != nil {
		t.Fatalf("get srv fd: %v", err)
	}
	clientFd, err := tcpFD(client)
	if err != nil {
		t.Fatalf("get client fd: %v", err)
	}

	r := NewResolver(100 * time.Millisecond)
	myPID := uint32(os.Getpid())

	srvInfo, err := r.Resolve(myPID, int32(srvFd))
	if err != nil {
		t.Fatalf("Resolve(srv): %v", err)
	}
	cliInfo, err := r.Resolve(myPID, int32(clientFd))
	if err != nil {
		t.Fatalf("Resolve(client): %v", err)
	}

	// The server side: local = listener address; remote = client address.
	// The client side: local = ephemeral; remote = listener address.
	if srvInfo.LocalPort != port {
		t.Errorf("srv.LocalPort = %d, want %d", srvInfo.LocalPort, port)
	}
	if cliInfo.RemotePort != port {
		t.Errorf("cli.RemotePort = %d, want %d", cliInfo.RemotePort, port)
	}
	if cliInfo.LocalPort != srvInfo.RemotePort {
		t.Errorf("cli.LocalPort (%d) != srv.RemotePort (%d)",
			cliInfo.LocalPort, srvInfo.RemotePort)
	}
	if !cliInfo.RemoteIP.Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("cli.RemoteIP = %v, want 127.0.0.1", cliInfo.RemoteIP)
	}
}

func tcpFD(c net.Conn) (int, error) {
	type syscallConner interface {
		SyscallConn() (interface{ Control(func(uintptr)) error }, error)
	}
	// Use the concrete type's File method which gives us a *os.File pointing
	// at a duplicate fd. This is simpler than SyscallConn for tests.
	type filer interface {
		File() (*os.File, error)
	}
	f, ok := c.(filer)
	if !ok {
		return 0, errNoFile
	}
	osf, err := f.File()
	if err != nil {
		return 0, err
	}
	return int(osf.Fd()), nil
}

var errNoFile = &fdErr{"conn does not expose File()"}

type fdErr struct{ s string }

func (e *fdErr) Error() string { return e.s }
