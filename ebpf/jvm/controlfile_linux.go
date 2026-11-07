//go:build linux

package jvm

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/postmanlabs/postman-insights-agent/ebpf/javatls"
)

// Files this agent writes into a JVM's container live in one directory,
// /tmp/.postman-insights (the directory of javatls.ControlFilePath).
var (
	agentDirParent = path.Dir(path.Dir(javatls.ControlFilePath))  // /tmp
	agentDirName   = path.Base(path.Dir(javatls.ControlFilePath)) // .postman-insights
	controlName    = path.Base(javatls.ControlFilePath)           // control
)

// errNoControlDir is returned when the agent directory does not exist and
// was not to be created.
var errNoControlDir = errors.New("no control directory")

// Every file this agent writes in a container is written by root into a
// directory root owns and nobody else can write to, and is reached through
// <procRoot>/<pid>/root with every path resolved inside the container
// (openat2 RESOLVE_IN_ROOT). Otherwise the container could plant a symlink
// that sends root's write anywhere on the node.

// errExited is returned when a JVM exited, even if its PID now belongs to
// another process.
var errExited = errors.New("the JVM exited")

// openRoot opens the root directory of p's container. It opens it through
// p's /proc/<pid> directory after checking the process's start time: the open
// directory keeps referring to the process it was opened for, so when p has
// exited and its PID was reused, this fails rather than opening the new
// process's container.
func openRoot(p *Process) (int, error) {
	dirPath := path.Join(p.ProcRoot, strconv.FormatUint(uint64(p.PID), 10))
	dir, err := unix.Open(dirPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open %s: %w", dirPath, err)
	}
	defer unix.Close(dir)
	if start, err := startTimeAt(dir); err != nil || start != p.StartTime {
		return -1, errExited
	}
	root, err := unix.Openat(dir, "root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open %s/root: %w", dirPath, err)
	}
	return root, nil
}

// startTimeAt returns the start time of the process whose /proc directory is
// open as dir.
func startTimeAt(dir int) (uint64, error) {
	fd, err := unix.Openat(dir, "stat", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	f := os.NewFile(uintptr(fd), "stat")
	defer f.Close()
	stat, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return 0, err
	}
	return parseStartTime(stat)
}

// openIn opens name inside the container whose root is open as root.
// Symlinks, absolute ones included, resolve inside the container.
func openIn(root int, name string, flags int, mode uint32) (int, error) {
	fd, err := unix.Openat2(root, name, &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC),
		Mode:    uint64(mode),
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if errors.Is(err, unix.ENOSYS) {
		return -1, fmt.Errorf("openat2 unsupported (Linux 5.6 or newer is required): %w", err)
	}
	return fd, err
}

// openAgentDir opens /tmp/.postman-insights in the container, creating it
// when create is set. It returns errNoControlDir when the directory does not
// exist and create is not set.
func openAgentDir(root int, create bool) (int, error) {
	// /tmp may itself be a symlink, which openIn resolves in the container.
	parent, err := openIn(root, agentDirParent, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return -1, fmt.Errorf("open %s: %w", agentDirParent, err)
	}
	defer unix.Close(parent)
	dir, err := openOwnedDir(parent, agentDirName, create)
	if errors.Is(err, unix.ENOENT) {
		return -1, errNoControlDir
	}
	if err != nil {
		return -1, fmt.Errorf("%s/%s: %w", agentDirParent, agentDirName, err)
	}
	return dir, nil
}

// openOwnedDir opens the directory name in parent, creating it (mode 0755)
// when create is set. It must not be a symlink, and must belong to this
// process with nobody else able to write to it, so nothing in the container
// can swap the files in it.
func openOwnedDir(parent int, name string, create bool) (int, error) {
	if create {
		if err := unix.Mkdirat(parent, name, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
			return -1, err
		}
	}
	dir, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(dir, &st); err != nil {
		unix.Close(dir)
		return -1, err
	}
	if int(st.Uid) != os.Geteuid() || st.Mode&0o022 != 0 {
		unix.Close(dir)
		return -1, fmt.Errorf("owned by uid %d with mode %o, not by this agent", st.Uid, st.Mode&0o7777)
	}
	return dir, nil
}

// writeFileAtomic writes content to name in dir, readable by every user, by
// renaming a temporary file over it, so a reader never sees a partly written
// file.
func writeFileAtomic(dir int, name string, content []byte) error {
	tmpName := name + ".tmp"
	f, err := unix.Openat(dir, tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmpName, err)
	}
	err = writeAll(f, content)
	if err == nil {
		// Readable by the JVM, whatever user it runs as.
		err = unix.Fchmod(f, 0o644)
	}
	if cerr := unix.Close(f); err == nil {
		err = cerr
	}
	if err == nil {
		err = unix.Renameat(dir, tmpName, dir, name)
	}
	if err != nil {
		_ = unix.Unlinkat(dir, tmpName, 0)
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

func writeAll(fd int, b []byte) error {
	for len(b) > 0 {
		n, err := unix.Write(fd, b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

// writeControl replaces the control file in p's container with content. With
// create false it writes only where the agent directory already exists, and
// returns errNoControlDir otherwise, so an Insights agent with Java capture
// off never adds files to a container.
func writeControl(p *Process, content []byte, create bool) error {
	root, err := openRoot(p)
	if err != nil {
		return err
	}
	defer unix.Close(root)
	return writeControlIn(root, content, create)
}

// writeControlIn is writeControl for a container whose root is open as root.
func writeControlIn(root int, content []byte, create bool) error {
	dir, err := openAgentDir(root, create)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	return writeFileAtomic(dir, controlName, content)
}
