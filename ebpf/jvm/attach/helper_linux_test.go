//go:build linux

package attach

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// fakeProcDir returns a directory standing in for /proc/<pid>, whose root
// has a /tmp, and that /tmp.
func fakeProcDir(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	tmp := filepath.Join(dir, "root", "tmp")
	require.NoError(t, os.MkdirAll(tmp, 0o1777))
	if _, err := unix.Openat2(unix.AT_FDCWD, tmp, &unix.OpenHow{Flags: unix.O_PATH}); errors.Is(err, unix.ENOSYS) {
		t.Skip("openat2 is not available")
	}
	return dir, tmp
}

// Only the attach that creates the trigger file owns it, signals and removes
// it; another one waits for the listener.
func TestCreateTriggerOwnership(t *testing.T) {
	dir, tmp := fakeProcDir(t)
	trigger := filepath.Join(tmp, ".attach_pid1")

	releaseFirst, owned, err := createTrigger(dir, ".attach_pid1")
	require.NoError(t, err)
	assert.True(t, owned)
	assert.FileExists(t, trigger)

	releaseSecond, owned, err := createTrigger(dir, ".attach_pid1")
	require.NoError(t, err)
	assert.False(t, owned, "a second attach owns the trigger too")
	releaseSecond()
	assert.FileExists(t, trigger, "removed by an attach that does not own it")

	releaseFirst()
	assert.NoFileExists(t, trigger)
}

// A trigger left by an attach that was killed is taken over.
func TestCreateTriggerTakesOverStale(t *testing.T) {
	dir, tmp := fakeProcDir(t)
	trigger := filepath.Join(tmp, ".attach_pid1")
	require.NoError(t, os.WriteFile(trigger, nil, 0o600))
	old := time.Now().Add(-2 * staleTriggerAge)
	require.NoError(t, os.Chtimes(trigger, old, old))

	release, owned, err := createTrigger(dir, ".attach_pid1")
	require.NoError(t, err)
	assert.True(t, owned)
	release()
	assert.NoFileExists(t, trigger)
}

// inspectFake runs OpInspect on a fake /proc/<pid> directory.
func inspectFake(t *testing.T, dir string, nspid uint32) Result {
	t.Helper()
	pidfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	require.NoError(t, err)
	defer unix.Close(pidfd)
	return inspect(pidfd, nspid)
}

func TestInspectPerfData(t *testing.T) {
	dir, tmp := fakeProcDir(t)
	perf := filepath.Join(tmp, "hsperfdata_app")
	require.NoError(t, os.Mkdir(perf, 0o755))
	data := perfData(binary.LittleEndian, map[string]string{
		"java.rt.vmArgs":         "-XX:+DisableAttachMechanism",
		"java.rt.vmFlags":        "-XX:Flags=.hotspotrc",
		"sun.rt.jvmCapabilities": "0100000000000000000000000000000000000000000000000000000000000000",
	})
	require.NoError(t, os.WriteFile(filepath.Join(perf, "7"), data, 0o600))
	// Never read when there is perf data.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "environ"), []byte("JAVA_TOOL_OPTIONS=-Xmx1g\x00"), 0o400))

	res := inspectFake(t, dir, 7)
	require.Equal(t, Inspected, res.Outcome, "%+v", res)
	assert.Equal(t, &Inspection{PerfData: map[string]string{
		"java.rt.vmArgs":         "-XX:+DisableAttachMechanism",
		"java.rt.vmFlags":        "-XX:Flags=.hotspotrc",
		"sun.rt.jvmCapabilities": "0100000000000000000000000000000000000000000000000000000000000000",
	}}, res.Inspection)

	// Another JVM's file: the environment instead.
	res = inspectFake(t, dir, 8)
	require.Equal(t, Inspected, res.Outcome, "%+v", res)
	assert.Equal(t, &Inspection{JavaOptions: map[string]string{"JAVA_TOOL_OPTIONS": "-Xmx1g"}}, res.Inspection)
}

// Perf data that is not a regular file of the helper's user, or that a
// symlink planted in the container's /tmp points to, is not read.
func TestInspectPerfDataUntrusted(t *testing.T) {
	dir, tmp := fakeProcDir(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "environ"), nil, 0o400))
	data := perfData(binary.LittleEndian, map[string]string{"java.rt.vmArgs": "-Xmx1g"})

	// A symlink to a directory outside the container resolves inside it.
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "1"), data, 0o600))
	require.NoError(t, os.Symlink(outside, filepath.Join(tmp, "hsperfdata_evil")))
	// A symlinked file is not followed.
	link := filepath.Join(tmp, "hsperfdata_link")
	require.NoError(t, os.Mkdir(link, 0o755))
	require.NoError(t, os.Symlink(filepath.Join(outside, "1"), filepath.Join(link, "1")))
	res := inspectFake(t, dir, 1)
	require.Equal(t, Inspected, res.Outcome, "%+v", res)
	assert.Nil(t, res.Inspection.PerfData)

	if os.Geteuid() != 0 {
		t.Skip("chown needs root")
	}
	other := filepath.Join(tmp, "hsperfdata_other")
	require.NoError(t, os.Mkdir(other, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(other, "2"), data, 0o600))
	require.NoError(t, os.Chown(filepath.Join(other, "2"), 4242, 4242))
	res = inspectFake(t, dir, 2)
	require.Equal(t, Inspected, res.Outcome, "%+v", res)
	assert.Nil(t, res.Inspection.PerfData, "a file of another user")
}

func TestInspectNoEnviron(t *testing.T) {
	dir, _ := fakeProcDir(t)
	res := inspectFake(t, dir, 1)
	assert.Equal(t, Failed, res.Outcome)
	assert.Equal(t, ReasonInspectFailed, res.Reason)
}

// Each op needs its own fields.
func TestRunBadRequests(t *testing.T) {
	base := Request{Version: RequestVersion1, ProcRoot: "/proc", PID: 1, NSPID: 1}
	for name, req := range map[string]Request{
		"no op":            base,
		"unknown op":       func() Request { r := base; r.Op = "detach"; return r }(),
		"attach, no jar":   func() Request { r := base; r.Op = OpAttach; return r }(),
		"inspect, no pid":  func() Request { r := base; r.Op = OpInspect; r.PID = 0; return r }(),
		"inspect, version": func() Request { r := base; r.Op = OpInspect; r.Version = 2; return r }(),
	} {
		assert.Equal(t, ReasonBadRequest, Run(req).Reason, name)
	}
}
