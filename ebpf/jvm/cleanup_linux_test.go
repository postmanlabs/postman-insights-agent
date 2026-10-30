//go:build linux

package jvm

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestParseMapsLine(t *testing.T) {
	start, end, id, ok := parseMapsLine("7f2c4a400000-7f2c4a401000 r--s 00000000 00:c9 1559355                    /tmp/.postman-insights/agent-0123/postman-insights-java-agent.jar")
	require.True(t, ok)
	assert.Equal(t, uint64(0x7f2c4a400000), start)
	assert.Equal(t, uint64(0x7f2c4a401000), end)
	assert.Equal(t, fileID{0, 0xc9, 1559355}, id)

	_, _, id, ok = parseMapsLine("55d0c0a00000-55d0c0a21000 r-xp 00001000 103:02 42 /usr/bin/sleep")
	require.True(t, ok)
	assert.Equal(t, fileID{0x103, 2, 42}, id, "device numbers are hexadecimal")

	for _, line := range []string{
		"7ffd1b2a0000-7ffd1b2c1000 rw-p 00000000 00:00 0                          [stack]",
		"7f2c4a400000-7f2c4a401000 rw-p 00000000 00:00 0",
		"garbage",
		"7f2c4a400000 r--s 00000000 00:c9 1559355 /x",
	} {
		_, _, _, ok := parseMapsLine(line)
		assert.False(t, ok, line)
	}
}

// The identity a mapping shows in /proc/self/maps is the file's.
func TestMappedID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	require.NoError(t, os.WriteFile(path, []byte("content"), 0o644))
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	require.NoError(t, err)
	defer unix.Close(fd)
	id, err := mappedID(fd)
	require.NoError(t, err)
	var st unix.Stat_t
	require.NoError(t, unix.Fstat(fd, &st))
	assert.Equal(t, statID(&st), id)
}

// startContainer starts a process with a private /tmp, standing in for a
// container, and returns it.
func startContainer(t *testing.T) *Process {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a mount namespace")
	}
	for _, tool := range []string{"unshare", "nsenter"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not found", tool)
		}
	}
	child := exec.Command("unshare", "--mount", "--propagation", "private", "sh", "-c",
		"mount -t tmpfs tmpfs /tmp && echo ready && exec sleep 600")
	waitReady(t, child)
	var p *Process
	require.Eventually(t, func() bool {
		start, err := StartTime("/proc", uint32(child.Process.Pid))
		if err != nil {
			return false
		}
		p = &Process{ProcRoot: "/proc", PID: uint32(child.Process.Pid), StartTime: start}
		return true
	}, 5*time.Second, 50*time.Millisecond)
	return p
}

// waitReady starts cmd, waits until it prints "ready", and kills it when the
// test ends.
func waitReady(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	sc := bufio.NewScanner(stdout)
	require.True(t, sc.Scan(), "no output from %v", cmd.Args)
	require.Equal(t, "ready", sc.Text())
}

// inContainer runs a shell script in p's mount namespace, and waits until it
// prints "ready".
func inContainer(t *testing.T, p *Process, script string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("nsenter", "-t", strconv.Itoa(int(p.PID)), "-m", "sh", "-c", script)
	waitReady(t, cmd)
	return cmd
}

func stopHolder(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	require.NoError(t, cmd.Process.Kill())
	_ = cmd.Wait()
}

// A container with copies of several versions: removed are those no process
// has open or mapped, and nothing else.
func TestRemoveStaleCopies(t *testing.T) {
	p := startContainer(t)
	agentDir := filepath.Join("/proc", strconv.Itoa(int(p.PID)), "root", agentDirParent, agentDirName)
	root, err := openRoot(p)
	require.NoError(t, err)
	defer unix.Close(root)

	// Nothing staged yet.
	res, err := removeStaleCopiesIn("/proc", root, "agent-keep")
	require.NoError(t, err)
	assert.Empty(t, res.removed)

	for _, name := range []string{"agent-keep", "agent-free", "agent-open", "agent-mapped", "agent-nested"} {
		_, err := stageIn(root, []byte("PK\x03\x04 "+name), name)
		require.NoError(t, err)
	}
	require.NoError(t, writeControlIn(root, []byte("enabled=1\n"), false))
	// A copy also holds an executable that a process runs, so it is mapped
	// but not open.
	sleep, err := exec.LookPath("sleep")
	require.NoError(t, err)
	sleepBin, err := os.ReadFile(sleep)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(agentDir, "agent-mapped", "sleep"), sleepBin, 0o755))
	// Never removed: what is not this agent's, what is not a directory, and
	// a directory with more than files in it.
	require.NoError(t, os.Mkdir(filepath.Join(agentDir, "agent-foreign"), 0o755))
	require.NoError(t, os.Chown(filepath.Join(agentDir, "agent-foreign"), 1000, 1000))
	require.NoError(t, os.Symlink("agent-free", filepath.Join(agentDir, "agent-link")))
	require.NoError(t, os.Mkdir(filepath.Join(agentDir, "agent-nested", "sub"), 0o755))
	require.NoError(t, os.Mkdir(filepath.Join(agentDir, "other"), 0o755))

	opener := inContainer(t, p, "exec 3</tmp/.postman-insights/agent-open/postman-insights-java-agent.jar && echo ready && exec sleep 600")
	mapper := inContainer(t, p, "echo ready && exec /tmp/.postman-insights/agent-mapped/sleep 600")
	// The shell prints "ready" before it runs the copy's executable.
	require.Eventually(t, func() bool {
		maps, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(mapper.Process.Pid), "maps"))
		return err == nil && strings.Contains(string(maps), "/agent-mapped/sleep")
	}, 10*time.Second, 10*time.Millisecond, "the copy's executable is not mapped")

	res, err = removeStaleCopiesIn("/proc", root, "agent-keep")
	require.NoError(t, err)
	assert.Equal(t, []string{"agent-free"}, res.removed)
	assert.Equal(t, map[string]uint32{
		"agent-open":   uint32(opener.Process.Pid),
		"agent-mapped": uint32(mapper.Process.Pid),
	}, res.held)
	assert.Equal(t, []string{"agent-foreign", "agent-keep", "agent-link", "agent-mapped", "agent-nested", "agent-open", "control", "other"}, entries(t, agentDir))

	// Once no process holds them, they go too.
	stopHolder(t, opener)
	stopHolder(t, mapper)
	res, err = removeStaleCopiesIn("/proc", root, "agent-keep")
	require.NoError(t, err)
	sort.Strings(res.removed)
	assert.Equal(t, []string{"agent-mapped", "agent-open"}, res.removed)
	assert.Empty(t, res.held)
	assert.Equal(t, []string{"agent-foreign", "agent-keep", "agent-link", "agent-nested", "control", "other"}, entries(t, agentDir))
	keep, err := os.ReadFile(filepath.Join(agentDir, "agent-keep", agentJarName))
	require.NoError(t, err)
	assert.Equal(t, "PK\x03\x04 agent-keep", string(keep))
}

// A process holds a copy only when it sees it in its own /tmp: one in
// another container that has the same file open does not count.
func TestRemoveStaleCopiesOtherContainer(t *testing.T) {
	p := startContainer(t)
	root, err := openRoot(p)
	require.NoError(t, err)
	defer unix.Close(root)
	_, err = stageIn(root, []byte("PK\x03\x04 old"), "agent-old")
	require.NoError(t, err)
	jar := filepath.Join("/proc", strconv.Itoa(int(p.PID)), "root", agentDirParent, agentDirName, "agent-old", agentJarName)
	f, err := os.Open(jar) // this test's process, outside the container
	require.NoError(t, err)
	defer f.Close()

	res, err := removeStaleCopiesIn("/proc", root, "agent-new")
	require.NoError(t, err)
	assert.Equal(t, []string{"agent-old"}, res.removed)
	content := make([]byte, 16)
	n, err := f.Read(content)
	require.NoError(t, err)
	assert.Equal(t, "PK\x03\x04 old", string(content[:n]), "an open copy stays readable once removed")
}

func entries(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, de := range des {
		names = append(names, de.Name())
	}
	return names
}
