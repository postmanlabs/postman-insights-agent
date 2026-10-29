//go:build linux

package jvm

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/postmanlabs/postman-insights-agent/ebpf/javatls"
)

// containerRoot returns a directory standing in for a container's root, with
// a /tmp, open as a directory fd.
func containerRoot(t *testing.T) (string, int) {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "tmp"), 0o1777))
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	require.NoError(t, err)
	t.Cleanup(func() { unix.Close(fd) })
	// openat2 needs Linux 5.6.
	if _, err := unix.Openat2(fd, "tmp", &unix.OpenHow{Flags: unix.O_PATH, Resolve: unix.RESOLVE_IN_ROOT}); errors.Is(err, unix.ENOSYS) {
		t.Skip("openat2 is not available")
	}
	return root, fd
}

func controlPath(root string) string {
	return filepath.Join(root, javatls.ControlFilePath)
}

func TestWriteControlCreatesAndReplaces(t *testing.T) {
	root, fd := containerRoot(t)
	content := javatls.Control{Enabled: true}.Marshal()
	require.NoError(t, writeControlIn(fd, content, true))

	got, err := os.ReadFile(controlPath(root))
	require.NoError(t, err)
	assert.Equal(t, content, got)

	dir, err := os.Stat(filepath.Dir(controlPath(root)))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), dir.Mode().Perm())
	file, err := os.Stat(controlPath(root))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), file.Mode().Perm(), "the JVM must be able to read it as any user")

	// A rewrite replaces the file and leaves no temporary file behind.
	disabled := javatls.Control{Enabled: false}.Marshal()
	require.NoError(t, writeControlIn(fd, disabled, true))
	got, _ = os.ReadFile(controlPath(root))
	assert.Equal(t, disabled, got)
	entries, _ := os.ReadDir(filepath.Dir(controlPath(root)))
	require.Len(t, entries, 1)
	assert.Equal(t, "control", entries[0].Name())
}

func TestWriteControlWithoutCreate(t *testing.T) {
	root, fd := containerRoot(t)
	assert.ErrorIs(t, writeControlIn(fd, []byte("x"), false), errNoControlDir)
	_, err := os.Stat(filepath.Dir(controlPath(root)))
	assert.True(t, os.IsNotExist(err), "the control directory was created")

	require.NoError(t, writeControlIn(fd, []byte("first"), true))
	require.NoError(t, writeControlIn(fd, []byte("second"), false))
	got, _ := os.ReadFile(controlPath(root))
	assert.Equal(t, "second", string(got))
}

// Symlinks in the container resolve inside it: a container cannot send the
// agent's writes anywhere else.
func TestWriteControlStaysInContainer(t *testing.T) {
	outside := t.TempDir()

	t.Run("absolute /tmp symlink", func(t *testing.T) {
		root, fd := containerRoot(t)
		require.NoError(t, os.Remove(filepath.Join(root, "tmp")))
		require.NoError(t, os.MkdirAll(filepath.Join(root, "var", "tmp"), 0o1777))
		require.NoError(t, os.Symlink("/var/tmp", filepath.Join(root, "tmp")))
		require.NoError(t, writeControlIn(fd, []byte("x"), true))
		_, err := os.Stat(filepath.Join(root, "var", "tmp", ".postman-insights", "control"))
		assert.NoError(t, err, "not written inside the container")
	})

	t.Run("/tmp symlink pointing outside", func(t *testing.T) {
		root, fd := containerRoot(t)
		require.NoError(t, os.Remove(filepath.Join(root, "tmp")))
		require.NoError(t, os.Symlink(outside, filepath.Join(root, "tmp")))
		assert.Error(t, writeControlIn(fd, []byte("x"), true))
		rel, err := filepath.Rel(root, outside)
		require.NoError(t, err)
		require.NoError(t, os.Remove(filepath.Join(root, "tmp")))
		require.NoError(t, os.Symlink(strings.Repeat("../", 20)+rel, filepath.Join(root, "tmp")))
		assert.Error(t, writeControlIn(fd, []byte("x"), true))
		entries, _ := os.ReadDir(outside)
		assert.Empty(t, entries, "written outside the container")
	})

	t.Run("control directory symlink", func(t *testing.T) {
		root, fd := containerRoot(t)
		require.NoError(t, os.Symlink(outside, filepath.Join(root, "tmp", ".postman-insights")))
		assert.Error(t, writeControlIn(fd, []byte("x"), true))
		entries, _ := os.ReadDir(outside)
		assert.Empty(t, entries, "written through a symlink")
	})
}

func TestWriteControlRefusesForeignDirectory(t *testing.T) {
	root, fd := containerRoot(t)
	dir := filepath.Dir(controlPath(root))
	require.NoError(t, os.Mkdir(dir, 0o755))
	require.NoError(t, os.Chmod(dir, 0o777)) // anyone could swap files in it
	assert.ErrorContains(t, writeControlIn(fd, []byte("x"), true), "not by this agent")

	if os.Geteuid() == 0 {
		require.NoError(t, os.Chmod(dir, 0o755))
		require.NoError(t, os.Chown(dir, 1000, 1000))
		assert.ErrorContains(t, writeControlIn(fd, []byte("x"), true), "not by this agent")
	}
}

// Through /proc/<pid>/root, the file lands in the process's own mount
// namespace: here a child with a private /tmp, as a container has. Root only.
func TestWriteControlThroughProc(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a mount namespace")
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare not found")
	}
	child := exec.Command("unshare", "--mount", "--propagation", "private", "sh", "-c",
		"mount -t tmpfs tmpfs /tmp && echo ready && exec sleep 60")
	stdout, err := child.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, child.Start())
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})
	buf := make([]byte, 6)
	_, err = stdout.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "ready\n", string(buf))

	// unshare execs sh, which execs sleep: the PID is the process in the new
	// namespace.
	var p *Process
	require.Eventually(t, func() bool {
		start, err := StartTime("/proc", uint32(child.Process.Pid))
		if err != nil {
			return false
		}
		p = &Process{ProcRoot: "/proc", PID: uint32(child.Process.Pid), StartTime: start}
		return true
	}, 5*time.Second, 50*time.Millisecond)

	content := javatls.Control{Enabled: true, CaptureCap: 2048}.Marshal()
	require.NoError(t, writeControl(p, content, true))

	got, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(child.Process.Pid), "root", javatls.ControlFilePath))
	require.NoError(t, err)
	assert.Equal(t, content, got)
	_, err = os.Stat(javatls.ControlFilePath)
	assert.True(t, os.IsNotExist(err), "written to this process's /tmp instead of the child's")
}

// A JVM's PID can belong to another process by the time its container is
// written: the start time must match.
func TestOpenRootChecksStartTime(t *testing.T) {
	pid := uint32(os.Getpid())
	start, err := StartTime("/proc", pid)
	require.NoError(t, err)

	root, err := openRoot(&Process{ProcRoot: "/proc", PID: pid, StartTime: start})
	require.NoError(t, err)
	unix.Close(root)

	_, err = openRoot(&Process{ProcRoot: "/proc", PID: pid, StartTime: start + 1})
	assert.ErrorIs(t, err, errExited)
	assert.ErrorIs(t, writeControl(&Process{ProcRoot: "/proc", PID: pid, StartTime: start + 1}, []byte("x"), true), errExited)
}

func TestStageJar(t *testing.T) {
	root, fd := containerRoot(t)
	jar := []byte("PK\x03\x04 a jar")
	got, err := stageIn(fd, jar, "agent-0123")
	require.NoError(t, err)
	assert.Equal(t, "/tmp/.postman-insights/agent-0123/postman-insights-java-agent.jar", got)
	content, err := os.ReadFile(filepath.Join(root, got))
	require.NoError(t, err)
	assert.Equal(t, jar, content)
	st, err := os.Stat(filepath.Join(root, got))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), st.Mode().Perm())

	// A second JVM in the container: staged once.
	before := st.ModTime()
	time.Sleep(10 * time.Millisecond)
	_, err = stageIn(fd, jar, "agent-0123")
	require.NoError(t, err)
	st, _ = os.Stat(filepath.Join(root, got))
	assert.Equal(t, before, st.ModTime())

	// A truncated copy is replaced.
	require.NoError(t, os.WriteFile(filepath.Join(root, got), jar[:3], 0o644))
	_, err = stageIn(fd, jar, "agent-0123")
	require.NoError(t, err)
	content, _ = os.ReadFile(filepath.Join(root, got))
	assert.Equal(t, jar, content)
}

func TestSigQuitCaught(t *testing.T) {
	assert.True(t, sigQuitCaught([]byte("Name:\tjava\nSigCgt:\t0000000181005ccf\n")))
	assert.False(t, sigQuitCaught([]byte("Name:\tjava\nSigCgt:\t0000000181005cca\n")), "-Xrs")
	assert.False(t, sigQuitCaught([]byte("Name:\tjava\n")))
}
