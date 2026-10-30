//go:build linux

package jvm

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// stagedPrefix starts the name of every staging directory in a container's
// agent directory: agent-<the first 16 hex digits of the jar's SHA-256>.
const stagedPrefix = "agent-"

func (o linuxOps) removeStaleCopies(p *Process, keep string) (cleanupResult, error) {
	root, err := openRoot(p)
	if err != nil {
		return cleanupResult{}, err
	}
	defer unix.Close(root)
	return removeStaleCopiesIn(p.ProcRoot, root, keep)
}

// removeStaleCopiesIn removes the staging directories other than keep from
// the agent directory of the container whose root is open as root, except
// those with a file that a process under procRoot has open or mapped.
//
// Each Insights agent version stages its own jar (4.7 MB), and nothing else
// removes the copies of earlier versions. A JVM that loaded one keeps it
// mapped for as long as it runs (on the bootstrap class path), so a copy in
// use is kept: removing it would free no space, and the JVM may open it again
// by name. Any process whose /tmp/.postman-insights is this directory can
// hold one, including JVMs in the pod's other containers when they share
// /tmp, so all of procRoot's processes are checked, not only the container's.
//
// Mappings are read from /proc/<pid>/maps, which this agent's SYS_PTRACE lets
// it read for every process. Open files are read from /proc/<pid>/fd where it
// may: that directory belongs to the process's user, and the agent has no
// capability that bypasses file permissions. A holder it misses comes to no
// harm: an open or mapped file stays readable after its name is removed.
func removeStaleCopiesIn(procRoot string, root int, keep string) (cleanupResult, error) {
	var res cleanupResult
	agentDir, err := openAgentDir(root, false)
	if errors.Is(err, errNoControlDir) {
		return res, nil
	}
	if err != nil {
		return res, err
	}
	defer unix.Close(agentDir)

	copies, err := stagedCopies(agentDir, keep)
	defer func() {
		for _, c := range copies {
			unix.Close(c.dir)
		}
	}()
	if err != nil || len(copies) == 0 {
		return res, err
	}
	var dirID unix.Stat_t
	if err := unix.Fstat(agentDir, &dirID); err != nil {
		return res, err
	}
	res.held = findHolders(procRoot, dirID, copies)

	var errs []error
	for _, c := range copies {
		if _, ok := res.held[c.name]; ok {
			continue
		}
		if err := c.remove(agentDir); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c.name, err))
			continue
		}
		res.removed = append(res.removed, c.name)
	}
	return res, errors.Join(errs...)
}

// fileID identifies a file as /proc/<pid>/maps shows it, or as stat does.
type fileID struct {
	major, minor uint32
	ino          uint64
}

func statID(st *unix.Stat_t) fileID {
	return fileID{unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)), st.Ino}
}

// stagedCopy is a staging directory that may be removed.
type stagedCopy struct {
	name  string
	dir   int
	files []string
	// opened identifies its files as stat shows them (through
	// /proc/<pid>/fd), mapped as /proc/<pid>/maps does.
	opened, mapped map[fileID]bool
}

// stagedCopies opens the staging directories in agentDir other than keep. It
// leaves out those it cannot fully remove: anything not owned by this agent
// (openOwnedDir), and directories with anything but regular files in them.
func stagedCopies(agentDir int, keep string) ([]*stagedCopy, error) {
	names, err := readDirNames(agentDir)
	if err != nil {
		return nil, err
	}
	var copies []*stagedCopy
	for _, name := range names {
		if !strings.HasPrefix(name, stagedPrefix) || name == keep {
			continue
		}
		dir, err := openOwnedDir(agentDir, name, false)
		if err != nil {
			continue
		}
		c := &stagedCopy{name: name, dir: dir, opened: map[fileID]bool{}, mapped: map[fileID]bool{}}
		if c.identify() != nil {
			unix.Close(dir)
			continue
		}
		copies = append(copies, c)
	}
	return copies, nil
}

// identify lists the copy's files and how processes would show them.
func (c *stagedCopy) identify() error {
	names, err := readDirNames(c.dir)
	if err != nil {
		return err
	}
	for _, name := range names {
		fd, err := unix.Openat(c.dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		var st unix.Stat_t
		err = unix.Fstat(fd, &st)
		if err == nil && st.Mode&unix.S_IFMT != unix.S_IFREG {
			err = fmt.Errorf("%s is not a regular file", name)
		}
		if err == nil {
			c.opened[statID(&st)] = true
			if st.Size > 0 {
				var id fileID
				if id, err = mappedID(fd); err == nil {
					c.mapped[id] = true
				}
			}
		}
		unix.Close(fd)
		if err != nil {
			return err
		}
		c.files = append(c.files, name)
	}
	return nil
}

// remove deletes the copy's files, then the copy.
func (c *stagedCopy) remove(agentDir int) error {
	for _, name := range c.files {
		if err := unix.Unlinkat(c.dir, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
	}
	return unix.Unlinkat(agentDir, c.name, unix.AT_REMOVEDIR)
}

// mappedID returns the identity /proc/<pid>/maps shows for the file open as
// fd. It is the file's own on most file systems, but on overlayfs some kernels
// show the underlying file's, so it is read from a mapping of the file in this
// process's own maps.
func mappedID(fd int) (fileID, error) {
	b, err := unix.Mmap(fd, 0, 1, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return fileID{}, err
	}
	defer unix.Munmap(b)
	addr := uint64(uintptr(unsafe.Pointer(&b[0])))
	f, err := os.Open("/proc/self/maps")
	if err != nil {
		return fileID{}, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		start, end, id, ok := parseMapsLine(sc.Text())
		if ok && start <= addr && addr < end {
			return id, nil
		}
	}
	return fileID{}, errors.New("the mapping is not in /proc/self/maps")
}

// parseMapsLine parses a /proc/<pid>/maps line: "start-end perms offset
// major:minor inode path", with hexadecimal addresses and device numbers.
// ok is false for anonymous mappings (inode 0) and malformed lines.
func parseMapsLine(line string) (start, end uint64, id fileID, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return 0, 0, id, false
	}
	lo, hi, ok1 := strings.Cut(fields[0], "-")
	major, minor, ok2 := strings.Cut(fields[3], ":")
	if !ok1 || !ok2 {
		return 0, 0, id, false
	}
	var maj, min uint64
	var errs [5]error
	start, errs[0] = strconv.ParseUint(lo, 16, 64)
	end, errs[1] = strconv.ParseUint(hi, 16, 64)
	maj, errs[2] = strconv.ParseUint(major, 16, 32)
	min, errs[3] = strconv.ParseUint(minor, 16, 32)
	id.ino, errs[4] = strconv.ParseUint(fields[4], 10, 64)
	if errors.Join(errs[:]...) != nil || id.ino == 0 {
		return 0, 0, fileID{}, false
	}
	id.major, id.minor = uint32(maj), uint32(min)
	return start, end, id, true
}

// findHolders returns, for each copy a process under procRoot has a file of
// open or mapped, one such process. Only processes whose agent directory is
// agentDir (by identity) are checked.
func findHolders(procRoot string, agentDir unix.Stat_t, copies []*stagedCopy) map[string]uint32 {
	held := map[string]uint32{}
	f, err := os.Open(procRoot)
	if err != nil {
		return held
	}
	pids, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return held
	}
	for _, name := range pids {
		pid, err := strconv.ParseUint(name, 10, 32)
		if err != nil {
			continue
		}
		if len(held) == len(copies) {
			break
		}
		for _, c := range holdersIn(procRoot+"/"+name, agentDir, copies) {
			if _, ok := held[c]; !ok {
				held[c] = uint32(pid)
			}
		}
	}
	return held
}

// holdersIn returns the names of the copies the process whose /proc directory
// is procDir has a file of open or mapped, when its agent directory is
// agentDir.
func holdersIn(procDir string, agentDir unix.Stat_t, copies []*stagedCopy) []string {
	dir, err := unix.Open(procDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil
	}
	defer unix.Close(dir)
	if !sharesAgentDir(dir, agentDir) {
		return nil
	}
	found := map[string]bool{}
	if fd, err := unix.Openat(dir, "maps", unix.O_RDONLY|unix.O_CLOEXEC, 0); err == nil {
		f := os.NewFile(uintptr(fd), "maps")
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if _, _, id, ok := parseMapsLine(sc.Text()); ok {
				for _, c := range copies {
					if c.mapped[id] {
						found[c.name] = true
					}
				}
			}
		}
		f.Close()
	}
	// Readable only for processes of this agent's user (see
	// removeStaleCopiesIn).
	if fds, err := unix.Openat(dir, "fd", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err == nil {
		names, _ := readDirNames(fds)
		for _, n := range names {
			var st unix.Stat_t
			if unix.Fstatat(fds, n, &st, 0) != nil {
				continue
			}
			for _, c := range copies {
				if c.opened[statID(&st)] {
					found[c.name] = true
				}
			}
		}
		unix.Close(fds)
	}
	var names []string
	for _, c := range copies {
		if found[c.name] {
			names = append(names, c.name)
		}
	}
	return names
}

// sharesAgentDir reports whether the agent directory of the process whose
// /proc directory is open as dir is agentDir.
func sharesAgentDir(dir int, agentDir unix.Stat_t) bool {
	root, err := unix.Openat(dir, "root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(root)
	theirs, err := openAgentDir(root, false)
	if err != nil {
		return false
	}
	defer unix.Close(theirs)
	var st unix.Stat_t
	return unix.Fstat(theirs, &st) == nil && st.Dev == agentDir.Dev && st.Ino == agentDir.Ino
}

// readDirNames lists the directory open as dir. It reads through a new open
// of the directory, so dir's own position is left alone.
func readDirNames(dir int) ([]string, error) {
	fd, err := unix.Openat(dir, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "dir")
	defer f.Close()
	return f.Readdirnames(-1)
}
