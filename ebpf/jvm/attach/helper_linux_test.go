// SPDX-License-Identifier: Apache-2.0

//go:build linux

package attach

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
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
		"probe, no nspid":  func() Request { r := base; r.Op = OpProbe; r.NSPID = 0; return r }(),
		"inspect, no pid":  func() Request { r := base; r.Op = OpInspect; r.PID = 0; return r }(),
		"inspect, version": func() Request { r := base; r.Op = OpInspect; r.Version = 2; return r }(),
	} {
		assert.Equal(t, ReasonBadRequest, Run(req).Reason, name)
	}
}

// A probe is a request of its own, which needs no jar.
func TestRunProbeNeedsNoJar(t *testing.T) {
	req := Request{Version: RequestVersion1, Op: OpProbe, ProcRoot: t.TempDir(), PID: 1, NSPID: 1}
	assert.Equal(t, ReasonProcessGone, Run(req).Reason)
}

// scriptedJVM stands in for a JVM's attach listener at sock: it answers each
// command with the next reply scripted for it. The returned func lists the
// commands it got.
func scriptedJVM(t *testing.T, sock string, replies map[string][]string) func() []string {
	t.Helper()
	l, err := net.Listen("unix", sock)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	var mu sync.Mutex
	var cmds []string
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			// A request is five NUL-terminated fields: the protocol
			// version, the command and three arguments.
			var fields []string
			var field []byte
			buf := make([]byte, 1)
			for len(fields) < 5 {
				if _, err := c.Read(buf); err != nil {
					break
				}
				if buf[0] == 0 {
					fields = append(fields, string(field))
					field = nil
					continue
				}
				field = append(field, buf[0])
			}
			if len(fields) == 5 {
				mu.Lock()
				cmds = append(cmds, fields[1])
				reply := "1\nunexpected command\n"
				if r := replies[fields[1]]; len(r) > 0 {
					reply, replies[fields[1]] = r[0], r[1:]
				}
				mu.Unlock()
				_, _ = io.WriteString(c, reply)
			}
			c.Close()
		}
	}()
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), cmds...)
	}
}

// An attach reports what the agent recorded after the load: running, failed,
// or nothing at all, when it could not open its jar (agent_not_started), so
// the Insights agent can stage the jar again and retry.
func TestRunAttachOutcomes(t *testing.T) {
	const none = "0\n#Tue Nov 04\njava.version=21\n"
	for _, tc := range []struct {
		name    string
		replies map[string][]string
		outcome Outcome
		reason  string
		cmds    []string
	}{
		{
			name:    "attached",
			replies: map[string][]string{"properties": {none, "0\npostman.insights.agent.version=1.2.3\n"}, "load": {"0\nreturn code: 0\n"}},
			outcome: Attached, cmds: []string{"properties", "load", "properties"},
		},
		{
			name:    "agent not started",
			replies: map[string][]string{"properties": {none, none}, "load": {"0\nreturn code: 0\n"}},
			outcome: Failed, reason: ReasonAgentNotStarted, cmds: []string{"properties", "load", "properties"},
		},
		{
			name:    "agent failed",
			replies: map[string][]string{"properties": {none, "0\npostman.insights.agent.failed=1.2.3\\: boom\n"}, "load": {"0\nreturn code: 0\n"}},
			outcome: Failed, reason: ReasonAgentFailed, cmds: []string{"properties", "load", "properties"},
		},
		{
			name:    "jar not loaded",
			replies: map[string][]string{"properties": {none}, "load": {"0\nreturn code: 100\n"}},
			outcome: Failed, reason: ReasonLoadFailed, cmds: []string{"properties", "load"},
		},
		{
			name:    "failed earlier",
			replies: map[string][]string{"properties": {"0\npostman.insights.agent.failed=1.2.3\\: boom\n"}},
			outcome: Failed, reason: ReasonEarlierFailure, cmds: []string{"properties"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			procRoot := t.TempDir()
			procDir := filepath.Join(procRoot, "7")
			tmp := filepath.Join(procDir, "root", "tmp")
			require.NoError(t, os.MkdirAll(tmp, 0o755))
			// Field 22, the start time, is 4200.
			require.NoError(t, os.WriteFile(filepath.Join(procDir, "stat"),
				[]byte("7 (java) S 1 7 7 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 4200 0 0\n"), 0o644))
			cmds := scriptedJVM(t, filepath.Join(tmp, ".java_pid7"), tc.replies)

			res := Run(Request{Version: RequestVersion1, Op: OpAttach, ProcRoot: procRoot, PID: 7, StartTime: 4200, NSPID: 7,
				JarPath: "/tmp/.postman-insights/agent-0123/postman-insights-java-agent.jar"})
			assert.Equal(t, tc.outcome, res.Outcome, res.Detail)
			assert.Equal(t, tc.reason, res.Reason, res.Detail)
			assert.False(t, res.Signalled)
			assert.Equal(t, tc.cmds, cmds())
		})
	}
}
