//go:build linux

package pcap

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/akitasoftware/go-utils/optionals"
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
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a network namespace and open a capture socket")
	}

	// Capture goes through the same path as the DaemonSet: GetPcapHandle
	// enters the namespace by its path, as it does for a pod.
	netnsPath := newIdleNetns(t)

	done := make(chan struct{})
	p := &pcapImpl{}
	pkts, err := p.capturePackets(done, "lo", "", optionals.Some(netnsPath), capturestats.New(), nil)
	require.NoError(t, err)

	// Let the reader settle into waiting for packets before stopping capture.
	time.Sleep(500 * time.Millisecond)
	close(done)

	// gopacket closes the packet channel only after the handle is closed, so a
	// closed channel shows that Close returned.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-pkts:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("capture handle was not closed within 5s of stopping capture on an idle interface")
		}
	}
}

// newIdleNetns creates a network namespace that holds only lo, brought up and
// with nothing sending on it, and returns a path that refers to it.
func newIdleNetns(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "netns")
	f, err := os.Create(path)
	require.NoError(t, err)
	require.NoError(t, f.Close())

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
	require.NoError(t, <-errCh)

	// Registered after t.TempDir, so it runs before the directory is removed.
	t.Cleanup(func() {
		_ = unix.Unmount(path, unix.MNT_DETACH)
	})
	return path
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
