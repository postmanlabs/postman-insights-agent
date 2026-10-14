// SPDX-License-Identifier: Apache-2.0

package jvm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/postmanlabs/postman-insights-agent/ebpf/jvm/attach"
)

// fakeOps stands in for real JVMs.
type fakeOps struct {
	info     gateInfo
	infoErr  error
	stageErr error
	dead     bool
	result   attach.Result
	helper   error
	requests []attach.Request
}

func (f *fakeOps) alive(*Process) bool                { return !f.dead }
func (f *fakeOps) inspect(*Process) (gateInfo, error) { return f.info, f.infoErr }
func (f *fakeOps) stage(*Process, []byte, string) (string, error) {
	return "/tmp/.postman-insights/agent-x/postman-java-agent.jar", f.stageErr
}

func (f *fakeOps) attach(_ context.Context, _ *Process, req attach.Request) (attach.Result, error) {
	f.requests = append(f.requests, req)
	return f.result, f.helper
}

func newTestAttacher() (*Attacher, *fakeOps) {
	ops := &fakeOps{
		info:   gateInfo{age: time.Minute, args: "-Xmx1g", argsSource: "hsperfdata", sigQuitCaught: true},
		result: attach.Result{Outcome: attach.Attached, AgentVersion: "1.0.0", Signalled: true},
	}
	return newAttacher(ops, []byte("jar"), "0123456789abcdef0123", func() string { return "cap=4096" }), ops
}

// attempt adds p and makes one attach attempt for it.
func attempt(t *testing.T, a *Attacher, p *Process) *attachState {
	t.Helper()
	a.Add(p)
	s := a.next(time.Now())
	require.NotNil(t, s)
	a.try(context.Background(), s)
	return s
}

func hotspot() *Process {
	return &Process{ProcRoot: "/host/proc", PID: 42, StartTime: 4200, NSPID: 1, UID: 1000, GID: 1000, Kind: HotSpot, MountNS: 9}
}

func TestAttacherAttaches(t *testing.T) {
	a, ops := newTestAttacher()
	s := attempt(t, a, hotspot())
	assert.True(t, s.done)
	require.Len(t, ops.requests, 1)
	req := ops.requests[0]
	assert.Equal(t, attach.Request{
		Version: attach.RequestVersion1, ProcRoot: "/host/proc", PID: 42, StartTime: 4200, NSPID: 1,
		JarPath: "/tmp/.postman-insights/agent-x/postman-java-agent.jar", AgentArgs: "cap=4096", AllowSignal: true,
	}, req)
	assert.Equal(t, "agent-0123456789abcdef", a.jarDir)
	st := a.Stats()
	assert.Equal(t, uint64(1), st.Seen)
	assert.Equal(t, uint64(1), st.Attached)

	// Added again (another subscription, or discovery again): nothing new.
	a.Add(hotspot())
	assert.Nil(t, a.next(time.Now()))
	assert.Equal(t, uint64(1), a.Stats().Seen)
}

func TestAttacherSignalsOnlyJVMsThatCatchSIGQUIT(t *testing.T) {
	a, ops := newTestAttacher()
	ops.info.sigQuitCaught = false // -Xrs
	ops.result = attach.Result{Outcome: attach.Failed, Reason: attach.ReasonNoListener}
	s := attempt(t, a, hotspot())
	assert.False(t, ops.requests[0].AllowSignal)
	assert.True(t, s.done)
	assert.Equal(t, uint64(1), a.Stats().Skipped[attach.ReasonNoListener])
}

func TestAttacherGates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		kind   Kind
		args   string
		reason string
	}{
		{"openj9", OpenJ9, "", SkipOpenJ9},
		{"attach disabled", HotSpot, "-XX:+DisableAttachMechanism", SkipAttachDisabled},
		{"dynamic loading disabled", HotSpot, "-XX:-EnableDynamicAgentLoading", SkipDynamicLoadingDisabled},
	} {
		a, ops := newTestAttacher()
		ops.info.args = tc.args
		p := hotspot()
		p.Kind = tc.kind
		s := attempt(t, a, p)
		assert.True(t, s.done, tc.name)
		assert.Empty(t, ops.requests, "%s: the helper ran", tc.name)
		assert.Equal(t, uint64(1), a.Stats().Skipped[tc.reason], tc.name)
	}
}

func TestAttacherStaticAgent(t *testing.T) {
	a, ops := newTestAttacher()
	ops.info.args = "-javaagent:/opt/postman/postman-java-agent.jar -jar app.jar"
	attempt(t, a, hotspot())
	assert.Empty(t, ops.requests)
	assert.Equal(t, uint64(1), a.Stats().AlreadyRunning)
}

func TestAttacherAlreadyLoaded(t *testing.T) {
	a, ops := newTestAttacher()
	ops.result = attach.Result{Outcome: attach.AlreadyLoaded, AgentVersion: "0.9.0"}
	attempt(t, a, hotspot())
	assert.Equal(t, uint64(1), a.Stats().AlreadyRunning)
	assert.Zero(t, a.Stats().Attached)
}

func TestAttacherWaitsForStartUp(t *testing.T) {
	a, ops := newTestAttacher()
	ops.info.age = time.Second
	s := attempt(t, a, hotspot())
	assert.False(t, s.done)
	assert.Empty(t, ops.requests)
	assert.Nil(t, a.next(time.Now()), "attempted again before start-up is over")
	assert.NotNil(t, a.next(time.Now().Add(minAge)))
}

func TestAttacherRetriesOnlyWithoutSignal(t *testing.T) {
	a, ops := newTestAttacher()
	ops.result = attach.Result{Outcome: attach.Failed, Reason: attach.ReasonConnectFailed}
	s := attempt(t, a, hotspot())
	for i := 1; i <= len(retryDelays); i++ {
		assert.False(t, s.done, "attempt %d", i)
		assert.Equal(t, i, s.attempts)
		assert.Nil(t, a.next(time.Now()), "retried before its delay")
		s = a.next(time.Now().Add(retryDelays[i-1] + time.Second))
		require.NotNil(t, s)
		a.try(context.Background(), s)
	}
	assert.True(t, s.done, "gives up after the last retry")
	assert.Equal(t, uint64(1), a.Stats().Failed[attach.ReasonConnectFailed])

	// After a signal: never again.
	a, ops = newTestAttacher()
	ops.result = attach.Result{Outcome: attach.Failed, Reason: attach.ReasonConnectFailed, Signalled: true}
	s = attempt(t, a, hotspot())
	assert.True(t, s.done)

	// The helper did not report: it may have signalled, so never again.
	a, ops = newTestAttacher()
	ops.helper = errors.New("helper crashed")
	s = attempt(t, a, hotspot())
	assert.True(t, s.done)
	assert.Equal(t, uint64(1), a.Stats().Failed[FailHelper])
}

func TestAttacherRetriesStagingAndInspection(t *testing.T) {
	a, ops := newTestAttacher()
	ops.stageErr = errors.New("read-only file system")
	s := attempt(t, a, hotspot())
	assert.False(t, s.done)
	assert.Empty(t, ops.requests)

	a, ops = newTestAttacher()
	ops.infoErr = errors.New("no such file")
	s = attempt(t, a, hotspot())
	assert.False(t, s.done)
}

func TestAttacherForgetsExitedJVMs(t *testing.T) {
	a, ops := newTestAttacher()
	ops.dead = true
	attempt(t, a, hotspot())
	assert.Empty(t, ops.requests)
	a.mu.Lock()
	assert.Empty(t, a.jvms)
	a.mu.Unlock()

	a, _ = newTestAttacher()
	a.Add(hotspot())
	a.Remove(hotspot().Key())
	assert.Nil(t, a.next(time.Now()))
}

func TestNewAttacherChecksum(t *testing.T) {
	dir := t.TempDir()
	helper, jar, sums := filepath.Join(dir, "helper"), filepath.Join(dir, "agent.jar"), filepath.Join(dir, "agent.jar.sha256")
	require.NoError(t, os.WriteFile(helper, nil, 0o755))
	require.NoError(t, os.WriteFile(jar, []byte("jar"), 0o644))
	sum := sha256.Sum256([]byte("jar"))
	cfg := AttacherConfig{HelperPath: helper, JarPath: jar, ChecksumPath: sums, AgentArgs: func() string { return "" }}

	for _, content := range []string{"", " \n"} {
		require.NoError(t, os.WriteFile(sums, []byte(content), 0o644))
		_, err := NewAttacher(cfg)
		assert.ErrorContains(t, err, "no checksum", "checksum file %q", content)
	}

	require.NoError(t, os.WriteFile(sums, []byte(strings.Repeat("0", 64)+"  agent.jar\n"), 0o644))
	_, err := NewAttacher(cfg)
	assert.ErrorContains(t, err, "SHA-256")

	require.NoError(t, os.WriteFile(sums, []byte(hex.EncodeToString(sum[:])+"  agent.jar\n"), 0o644))
	_, err = NewAttacher(cfg)
	if runtime.GOOS == "linux" {
		assert.NoError(t, err)
	} else {
		assert.ErrorIs(t, err, errAttachUnsupported)
	}
}
