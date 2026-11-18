//go:build linux

package pcap

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/akitasoftware/go-utils/optionals"
	"github.com/google/gopacket"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/capturestats"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// A capture on an interface that receives no packets must still release its
// handle when it is stopped. This is the case of a deleted pod: its interface
// goes quiet, and a handle that is never closed keeps its socket, its
// pcapBufSize ring and the pod's network namespace alive (INS-537).
func TestCapturePacketsReleasesHandleOnIdleInterface(t *testing.T) {
	netnsPath := idleNetnsOrSkip(t)

	done := make(chan struct{})
	p := &pcapImpl{}
	pkts, err := p.capturePackets(done, "lo", "", optionals.Some(netnsPath), capturestats.New(), nil)
	require.NoError(t, err)

	// Let the reader settle into waiting for packets before stopping capture.
	time.Sleep(500 * time.Millisecond)
	close(done)

	requireClosedWithin(t, pkts, 5*time.Second)
}

// Capture must also stop and release its handle when the consumer has stopped
// reading and the packet channel is full, as it does once done is closed.
func TestCapturePacketsReleasesHandleWhenConsumerStopsReading(t *testing.T) {
	netnsPath := idleNetnsOrSkip(t)

	stopSending := make(chan struct{})
	defer close(stopSending)
	sendUDPInNetns(t, netnsPath, stopSending)

	fdsBefore := openFDs(t)
	done := make(chan struct{})
	p := &pcapImpl{}
	pkts, err := p.capturePackets(done, "lo", "udp port 9999", optionals.Some(netnsPath), capturestats.New(), nil)
	require.NoError(t, err)

	// Read nothing until the channel is full.
	require.Eventually(t, func() bool { return len(pkts) == cap(pkts) }, 5*time.Second, 10*time.Millisecond,
		"packet channel did not fill up")
	close(done)

	// Still read nothing: a read would unblock a send stuck on the full
	// channel. Watch the handle's file descriptors go away instead.
	require.Eventually(t, func() bool { return openFDs(t) <= fdsBefore }, 5*time.Second, 10*time.Millisecond,
		"capture handle was not released within 5s of stopping capture with a full packet channel")
	requireClosedWithin(t, pkts, 5*time.Second)
}

// openFDs returns how many file descriptors the process has open.
func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	return len(entries)
}

// requireClosedWithin reads pkts until it is closed. capturePackets closes the
// channel only after it has closed the handle, so a closed channel shows that
// the handle was released.
func requireClosedWithin(t *testing.T, pkts <-chan gopacket.Packet, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case _, ok := <-pkts:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatalf("capture handle was not released within %s of stopping capture", timeout)
		}
	}
}

// idleNetnsOrSkip is newIdleNetns, skipping the test where namespaces cannot
// be set up. Capture then goes through the same path as the DaemonSet:
// GetPcapHandle enters the namespace by its path, as it does for a pod.
func idleNetnsOrSkip(t *testing.T) string {
	t.Helper()
	netnsPath, err := newIdleNetns(t)
	if errors.Is(err, unix.EPERM) {
		// Being root is not enough: an unprivileged container lacks
		// CAP_SYS_ADMIN, which creating and bind-mounting a namespace needs.
		t.Skipf("not permitted to set up a network namespace: %v", err)
	}
	require.NoError(t, err)
	return netnsPath
}

// sendUDPInNetns sends UDP packets to 127.0.0.1:9999 in the given network
// namespace until stop is closed.
func sendUDPInNetns(t *testing.T, netnsPath string, stop <-chan struct{}) {
	t.Helper()
	ready := make(chan error, 1)
	go func() {
		// Never unlocked, as in newIdleNetns: the thread joins the namespace.
		runtime.LockOSThread()
		f, err := os.Open(netnsPath)
		if err != nil {
			ready <- err
			return
		}
		defer f.Close()
		if err := unix.Setns(int(f.Fd()), unix.CLONE_NEWNET); err != nil {
			ready <- errors.Wrap(err, "enter network namespace")
			return
		}
		// A listener, so the sends are not refused.
		l, err := net.ListenPacket("udp", "127.0.0.1:9999")
		if err != nil {
			ready <- err
			return
		}
		defer l.Close()
		c, err := net.Dial("udp", "127.0.0.1:9999")
		if err != nil {
			ready <- err
			return
		}
		defer c.Close()
		ready <- nil
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = c.Write([]byte("hello"))
			time.Sleep(100 * time.Microsecond)
		}
	}()
	require.NoError(t, <-ready)
}

// newIdleNetns creates a network namespace that holds only lo, brought up and
// with nothing sending on it, and returns a path that refers to it.
func newIdleNetns(t *testing.T) (string, error) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "netns")
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}

	errCh := make(chan error, 1)
	go func() {
		// Never unlocked: the thread moves to the new namespace, and Go ends a
		// locked thread when its goroutine exits, so no other goroutine runs in
		// that namespace.
		runtime.LockOSThread()
		errCh <- func() error {
			if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
				return errors.Wrap(err, "unshare network namespace")
			}
			if err := setLinkUp("lo"); err != nil {
				return err
			}
			// Bind-mount the namespace so it outlives this thread.
			if err := unix.Mount("/proc/thread-self/ns/net", path, "", unix.MS_BIND, ""); err != nil {
				return errors.Wrap(err, "bind-mount network namespace")
			}
			return nil
		}()
	}()
	if err := <-errCh; err != nil {
		return "", err
	}

	// Registered after t.TempDir, so it runs before the directory is removed.
	t.Cleanup(func() {
		_ = unix.Unmount(path, unix.MNT_DETACH)
	})
	return path, nil
}

func setLinkUp(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return errors.Wrap(err, "open socket")
	}
	defer unix.Close(fd)

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return errors.Wrapf(err, "ifreq for %s", name)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return errors.Wrapf(err, "get flags of %s", name)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return errors.Wrapf(err, "bring up %s", name)
	}
	return nil
}
