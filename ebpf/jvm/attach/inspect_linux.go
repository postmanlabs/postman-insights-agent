// SPDX-License-Identifier: Apache-2.0

//go:build linux

package attach

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// inspect performs OpInspect for the JVM whose /proc directory is open as
// pidfd. It must run as the JVM's user: the files it reads are readable only
// by that user (perf data 0600, environ 0400), and the Insights agent reads
// them through this helper so it needs no capability that bypasses file
// permissions.
func inspect(pidfd int, nspid uint32) Result {
	root, err := unix.Openat(pidfd, "root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return failed(ReasonInspectFailed, false, "open the JVM's root: %v", err)
	}
	defer unix.Close(root)
	if entries, err := perfDataIn(root, nspid, uint32(os.Getuid())); err == nil {
		return Result{Outcome: Inspected, Inspection: &Inspection{PerfData: entries}}
	}
	// Without perf data (-XX:-UsePerfData, or a user with no name, for whom
	// HotSpot publishes none), the Insights agent reads the arguments from
	// the command line and these.
	environ, err := readAt(pidfd, "environ")
	if err != nil {
		return failed(ReasonInspectFailed, false, "read environ: %v", err)
	}
	return Result{Outcome: Inspected, Inspection: &Inspection{JavaOptions: javaOptions(environ)}}
}

// perfDataIn returns the PerfDataKeys entries of the perf data file of the JVM
// with PID nspid in its namespace, in the container whose root is open as
// root: /tmp/hsperfdata_<user>/<nspid>, which must be a regular file of uid.
func perfDataIn(root int, nspid, uid uint32) (map[string]string, error) {
	tmp, err := openIn(root, "/tmp", unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	tmpDir := os.NewFile(uintptr(tmp), "/tmp")
	names, err := tmpDir.Readdirnames(-1)
	tmpDir.Close()
	if err != nil {
		return nil, err
	}
	pid := strconv.FormatUint(uint64(nspid), 10)
	for _, name := range names {
		if !strings.HasPrefix(name, "hsperfdata_") {
			continue
		}
		data, err := readOwnedFile(root, path.Join("/tmp", name, pid), uid)
		if err != nil {
			continue
		}
		if entries, err := perfDataEntries(data); err == nil {
			return entries, nil
		}
	}
	return nil, errors.New("no perf data")
}

// readOwnedFile reads up to maxPerfDataSize bytes of a regular file inside the
// container that belongs to uid.
func readOwnedFile(root int, name string, uid uint32) ([]byte, error) {
	fd, err := openIn(root, name, unix.O_RDONLY|unix.O_NOFOLLOW)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uid {
		return nil, fmt.Errorf("%s: not a file of uid %d", name, uid)
	}
	return io.ReadAll(io.LimitReader(f, maxPerfDataSize))
}

// readAt reads the file name in the directory open as dir.
func readAt(dir int, name string) ([]byte, error) {
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	return io.ReadAll(f)
}

// openIn opens name inside the container whose root is open as root.
// Symlinks, absolute ones included, resolve inside the container.
func openIn(root int, name string, flags int) (int, error) {
	fd, err := unix.Openat2(root, name, &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if errors.Is(err, unix.ENOSYS) {
		return -1, fmt.Errorf("openat2 unsupported (Linux 5.6 or newer is required): %w", err)
	}
	return fd, err
}
