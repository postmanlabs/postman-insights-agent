// SPDX-License-Identifier: Apache-2.0

package jvm

import (
	"archive/zip"
	"bytes"
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
	// probe is the helper's answer to OpProbe; results are its answers to
	// the OpAttach requests in turn, then result to every later one.
	probe, result attach.Result
	results       []attach.Result
	helper        error
	// attachErrs are the helper's errors for the OpAttach requests in turn,
	// then helper for every later one.
	attachErrs []error
	requests   []attach.Request
	// stagedAt records the modification time each stage call set.
	stagedAt []time.Time
	staged   int
	// cleanups records each removeStaleCopies call.
	cleanups   []cleanupCall
	cleanup    cleanupResult
	cleanupErr error
}

type cleanupCall struct {
	keep       string
	youngAfter time.Time
}

func (f *fakeOps) alive(*Process) bool                                 { return !f.dead }
func (f *fakeOps) inspect(context.Context, *Process) (gateInfo, error) { return f.info, f.infoErr }
func (f *fakeOps) stage(_ *Process, _ []byte, _ string, now time.Time) (string, error) {
	f.staged++
	f.stagedAt = append(f.stagedAt, now)
	return "/tmp/.postman-insights/agent-x/postman-insights-java-agent.jar", f.stageErr
}

func (f *fakeOps) attach(_ context.Context, _ *Process, req attach.Request) (attach.Result, error) {
	f.requests = append(f.requests, req)
	if req.Op == attach.OpProbe {
		return f.probe, f.helper
	}
	err := f.helper
	if len(f.attachErrs) > 0 {
		err, f.attachErrs = f.attachErrs[0], f.attachErrs[1:]
	}
	if len(f.results) > 0 {
		res := f.results[0]
		f.results = f.results[1:]
		return res, err
	}
	return f.result, err
}

func (f *fakeOps) removeStaleCopies(_ *Process, keep string, youngAfter time.Time) (cleanupResult, error) {
	f.cleanups = append(f.cleanups, cleanupCall{keep, youngAfter})
	return f.cleanup, f.cleanupErr
}

// keeps returns the keep argument of each removeStaleCopies call.
func (f *fakeOps) keeps() []string {
	var keeps []string
	for _, c := range f.cleanups {
		keeps = append(keeps, c.keep)
	}
	return keeps
}

const testJarDir = "agent-0123456789abcdef"

func newTestAttacher() (*Attacher, *fakeOps) {
	ops := &fakeOps{
		info:   gateInfo{age: time.Minute, args: []string{"-Xmx1g"}, argsSource: "hsperfdata", sigQuitCaught: true},
		probe:  attach.Result{Outcome: attach.NotLoaded, Signalled: true},
		result: attach.Result{Outcome: attach.Attached, AgentVersion: "1.0.0"},
	}
	a := newAttacher(ops, []byte("jar"), "0123456789abcdef0123", func() string { return "cap=4096" })
	a.version = "1.0.0"
	return a, ops
}

// testClock is a clock tests move by hand.
type testClock struct{ t time.Time }

func (c *testClock) now() time.Time          { return c.t }
func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// withClock gives a a clock that tests move by hand.
func withClock(a *Attacher) *testClock {
	c := &testClock{t: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	a.now = c.now
	return c
}

// attempt adds p and makes one attach attempt for it.
func attempt(t *testing.T, a *Attacher, p *Process) *attachState {
	t.Helper()
	a.Add(p, nil)
	s := a.next(a.now())
	require.NotNil(t, s)
	a.try(context.Background(), s)
	return s
}

func hotspot() *Process {
	return &Process{ProcRoot: "/host/proc", PID: 42, StartTime: 4200, NSPID: 1, UID: 1000, GID: 1000, Kind: HotSpot, MountNS: 9}
}

// The helper probes the JVM, the jar is staged, the helper attaches, and the
// copies of other versions are removed.
func TestAttacherAttaches(t *testing.T) {
	a, ops := newTestAttacher()
	s := attempt(t, a, hotspot())
	assert.True(t, s.done)
	require.Len(t, ops.requests, 2)
	assert.Equal(t, attach.Request{
		Version: attach.RequestVersion1, Op: attach.OpProbe, ProcRoot: "/host/proc", PID: 42, StartTime: 4200, NSPID: 1,
		AllowSignal: true,
	}, ops.requests[0])
	// The probe started the listener with SIGQUIT: no second signal.
	assert.Equal(t, attach.Request{
		Version: attach.RequestVersion1, Op: attach.OpAttach, ProcRoot: "/host/proc", PID: 42, StartTime: 4200, NSPID: 1,
		JarPath: "/tmp/.postman-insights/agent-x/postman-insights-java-agent.jar", AgentArgs: "cap=4096",
	}, ops.requests[1])
	assert.Equal(t, 1, ops.staged)
	assert.Equal(t, testJarDir, a.jarDir)
	assert.Equal(t, []string{testJarDir}, ops.keeps())
	st := a.Stats()
	assert.Equal(t, uint64(1), st.Seen)
	assert.Equal(t, uint64(1), st.Attached)

	// Added again (another subscription, or discovery again): nothing new.
	a.Add(hotspot(), nil)
	assert.Nil(t, a.next(time.Now()))
	assert.Equal(t, uint64(1), a.Stats().Seen)
}

func TestAttacherSignalsOnlyJVMsThatCatchSIGQUIT(t *testing.T) {
	a, ops := newTestAttacher()
	ops.info.sigQuitCaught = false // -Xrs
	ops.probe = attach.Result{Outcome: attach.Failed, Reason: attach.ReasonNoListener}
	s := attempt(t, a, hotspot())
	assert.False(t, ops.requests[0].AllowSignal)
	assert.True(t, s.done)
	assert.Equal(t, uint64(1), a.Stats().Skipped[attach.ReasonNoListener])

	// The listener was running: the attach may not signal either.
	a, ops = newTestAttacher()
	ops.info.sigQuitCaught = false
	ops.probe.Signalled = false
	attempt(t, a, hotspot())
	require.Len(t, ops.requests, 2)
	assert.False(t, ops.requests[1].AllowSignal)

	// It was running, and the JVM catches SIGQUIT: the attach may signal
	// if it is gone by then, a first signal.
	a, ops = newTestAttacher()
	ops.probe.Signalled = false
	attempt(t, a, hotspot())
	require.Len(t, ops.requests, 2)
	assert.True(t, ops.requests[1].AllowSignal)
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
		ops.info.args = strings.Fields(tc.args)
		p := hotspot()
		p.Kind = tc.kind
		s := attempt(t, a, p)
		assert.True(t, s.done, tc.name)
		assert.Empty(t, ops.requests, "%s: the helper ran", tc.name)
		assert.Equal(t, uint64(1), a.Stats().Skipped[tc.reason], tc.name)
	}
}

// Where the JVM says whether attach is on (its perf data), that decides, not
// arguments, which HotSpot joins with spaces there: an argument containing
// " -XX:-DisableAttachMechanism" must not turn attach back on.
func TestAttacherGateFromJVM(t *testing.T) {
	a, ops := newTestAttacher()
	ops.info.args = strings.Fields("-XX:+DisableAttachMechanism -Dmsg=x -XX:-DisableAttachMechanism")
	ops.info.attachKnown, ops.info.attachOn = true, false
	assert.True(t, attempt(t, a, hotspot()).done)
	assert.Empty(t, ops.requests, "the helper ran")
	assert.Equal(t, uint64(1), a.Stats().Skipped[SkipAttachDisabled])

	a, ops = newTestAttacher()
	ops.info.args = strings.Fields("-Dmsg=x -XX:+DisableAttachMechanism") // one argument, split
	ops.info.attachKnown, ops.info.attachOn = true, true
	attempt(t, a, hotspot())
	assert.NotEmpty(t, ops.requests, "attach is on, whatever an argument contains")
}

func TestAttacherStaticAgent(t *testing.T) {
	a, ops := newTestAttacher()
	ops.info.args = []string{"-javaagent:/opt/postman/postman-insights-java-agent.jar", "-jar", "app.jar"}
	attempt(t, a, hotspot())
	assert.Empty(t, ops.requests)
	assert.Zero(t, ops.staged)
	assert.Equal(t, uint64(1), a.Stats().AlreadyRunning)
	assert.Len(t, ops.cleanups, 1)
}

// A JVM that runs the agent already gets no copy of the jar, and the copies of
// other versions are removed. One that runs another version than this
// Insights agent's is counted.
func TestAttacherAlreadyLoaded(t *testing.T) {
	for _, tc := range []struct {
		version, bundled string
		other            bool
	}{
		{version: "1.0.0", bundled: "1.0.0"},
		{version: "0.9.0", bundled: "1.0.0", other: true},
		// A jar without a version (a development build) compares with
		// nothing.
		{version: "unknown", bundled: ""},
	} {
		a, ops := newTestAttacher()
		a.version = tc.bundled
		ops.probe = attach.Result{Outcome: attach.AlreadyLoaded, AgentVersion: tc.version}
		assert.True(t, attempt(t, a, hotspot()).done)
		assert.Len(t, ops.requests, 1, "only probed")
		assert.Zero(t, ops.staged, "staged")
		assert.Equal(t, []string{testJarDir}, ops.keeps())
		st := a.Stats()
		assert.Equal(t, uint64(1), st.AlreadyRunning)
		assert.Zero(t, st.Attached)
		assert.Equal(t, tc.other, st.OtherVersion == 1, "%s, bundled %s", tc.version, tc.bundled)
	}
}

// A failed probe stages nothing. Once a failure is final, the other versions'
// unused copies are removed (this agent's own is kept for another JVM there);
// a failure that is retried removes nothing yet.
func TestAttacherProbeFails(t *testing.T) {
	for _, tc := range []struct {
		res   attach.Result
		final bool
	}{
		{attach.Result{Outcome: attach.Failed, Reason: attach.ReasonConnectFailed}, false},
		{attach.Result{Outcome: attach.Failed, Reason: attach.ReasonEarlierFailure, Detail: "1.0.0: boom"}, true},
		{attach.Result{Outcome: attach.Failed, Reason: attach.ReasonListenerTimeout, Signalled: true}, true},
	} {
		a, ops := newTestAttacher()
		ops.probe = tc.res
		s := attempt(t, a, hotspot())
		assert.Equal(t, tc.final, s.done, tc.res.Reason)
		assert.Len(t, ops.requests, 1, tc.res.Reason)
		assert.Zero(t, ops.staged, tc.res.Reason)
		if tc.final {
			assert.Equal(t, []string{testJarDir}, ops.keeps(), tc.res.Reason)
		} else {
			assert.Empty(t, ops.cleanups, tc.res.Reason)
		}
	}

	a, ops := newTestAttacher()
	ops.helper = errors.New("helper crashed")
	attempt(t, a, hotspot())
	assert.Zero(t, ops.staged)
	assert.Equal(t, []string{testJarDir}, ops.keeps())
	assert.Equal(t, uint64(1), a.Stats().Failed[FailHelper])

	// The attach after the probe fails for good.
	a, ops = newTestAttacher()
	ops.result = attach.Result{Outcome: attach.Failed, Reason: attach.ReasonAgentFailed, Detail: "1.0.0: boom"}
	attempt(t, a, hotspot())
	assert.Equal(t, []string{testJarDir}, ops.keeps())
	assert.Equal(t, uint64(1), a.Stats().Failed[attach.ReasonAgentFailed])

	// A JVM that exited: nothing to remove from.
	a, ops = newTestAttacher()
	ops.probe = attach.Result{Outcome: attach.Failed, Reason: attach.ReasonProcessGone}
	a.Add(hotspot(), nil)
	s := a.next(time.Now())
	require.NotNil(t, s)
	ops.dead = true
	a.fail(s, attach.ReasonProcessGone, false, "gone")
	assert.Empty(t, ops.cleanups)
}

// A load that fails as a removed copy would make it fail, because the JVM
// could not load the jar or the agent could not open it, is retried once,
// with the copy staged again and no signal.
func TestAttacherRetriesLoadOnce(t *testing.T) {
	for _, reason := range []string{attach.ReasonLoadFailed, attach.ReasonAgentNotStarted} {
		a, ops := newTestAttacher()
		clock := withClock(a)
		ops.results = []attach.Result{{Outcome: attach.Failed, Reason: reason}}
		assert.True(t, attempt(t, a, hotspot()).done, reason)
		require.Len(t, ops.requests, 3, reason)
		assert.Equal(t, attach.OpAttach, ops.requests[2].Op, reason)
		assert.Equal(t, ops.requests[1].JarPath, ops.requests[2].JarPath, reason)
		assert.False(t, ops.requests[2].AllowSignal, "%s: the retry may signal", reason)
		assert.Equal(t, []time.Time{clock.t, clock.t}, ops.stagedAt, "%s: staged again", reason)
		assert.Equal(t, uint64(1), a.Stats().Attached, reason)
		assert.Empty(t, a.Stats().Failed, reason)

		// The probe did not signal, and the JVM catches SIGQUIT: the first
		// attach may signal, the retry still not.
		a, ops = newTestAttacher()
		ops.probe.Signalled = false
		ops.results = []attach.Result{{Outcome: attach.Failed, Reason: reason}}
		attempt(t, a, hotspot())
		require.Len(t, ops.requests, 3, reason)
		assert.True(t, ops.requests[1].AllowSignal, reason)
		assert.False(t, ops.requests[2].AllowSignal, reason)

		// Only once.
		a, ops = newTestAttacher()
		ops.result = attach.Result{Outcome: attach.Failed, Reason: reason}
		assert.True(t, attempt(t, a, hotspot()).done, reason)
		assert.Len(t, ops.requests, 3, reason)
		assert.Equal(t, 2, ops.staged, reason)
		assert.Equal(t, uint64(1), a.Stats().Failed[reason], reason)
	}

	// Staging again fails: as any staging failure, retried later only
	// without a signal.
	a, ops := newTestAttacher()
	ops.probe.Signalled = false
	ops.results = []attach.Result{{Outcome: attach.Failed, Reason: attach.ReasonLoadFailed}}
	a.Add(hotspot(), nil)
	s := a.next(time.Now())
	require.NotNil(t, s)
	ops.stageErr = nil
	stage := &failingSecondStage{fakeOps: ops}
	a.ops = stage
	a.try(context.Background(), s)
	assert.False(t, s.done, "not retried later")
	assert.Len(t, ops.requests, 2)

	// Other failures are not retried at once.
	for _, reason := range []string{attach.ReasonAgentFailed, attach.ReasonConnectFailed, attach.ReasonProtocol} {
		a, ops := newTestAttacher()
		ops.result = attach.Result{Outcome: attach.Failed, Reason: reason}
		attempt(t, a, hotspot())
		assert.Len(t, ops.requests, 2, reason)
		assert.Equal(t, 1, ops.staged, reason)
	}
}

// failingSecondStage fails every stage call after the first.
type failingSecondStage struct {
	*fakeOps
}

func (f *failingSecondStage) stage(p *Process, jar []byte, dir string, now time.Time) (string, error) {
	path, err := f.fakeOps.stage(p, jar, dir, now)
	if f.staged > 1 {
		return "", errors.New("no space left on device")
	}
	return path, err
}

// Copies younger than stagingGrace are kept, and looked at again once they
// are older, while the JVM runs.
func TestAttacherCleanupGrace(t *testing.T) {
	a, ops := newTestAttacher()
	clock := withClock(a)
	ops.cleanup = cleanupResult{young: []string{"agent-other"}}
	attempt(t, a, hotspot())
	require.Len(t, ops.cleanups, 1)
	assert.Equal(t, cleanupCall{testJarDir, clock.t.Add(-stagingGrace)}, ops.cleanups[0])
	assert.Equal(t, []time.Time{clock.t}, ops.stagedAt, "the staged copy's time")

	ctx := context.Background()
	clock.advance(stagingGrace - time.Second)
	a.runDue(ctx)
	assert.Len(t, ops.cleanups, 1, "looked again too early")

	// Still young (another agent reused it): again later.
	clock.advance(time.Second)
	a.runDue(ctx)
	require.Len(t, ops.cleanups, 2)
	assert.Equal(t, cleanupCall{testJarDir, clock.t.Add(-stagingGrace)}, ops.cleanups[1])

	ops.cleanup = cleanupResult{removed: []string{"agent-other"}}
	clock.advance(stagingGrace)
	a.runDue(ctx)
	require.Len(t, ops.cleanups, 3)
	clock.advance(stagingGrace)
	a.runDue(ctx)
	assert.Len(t, ops.cleanups, 3, "looked again with nothing young left")

	// The JVM exited before the second look: nothing more.
	a, ops = newTestAttacher()
	clock = withClock(a)
	ops.cleanup = cleanupResult{young: []string{"agent-other"}}
	attempt(t, a, hotspot())
	ops.dead = true
	clock.advance(stagingGrace)
	a.runDue(ctx)
	assert.Len(t, ops.cleanups, 1)
	a.mu.Lock()
	assert.Empty(t, a.cleanups)
	a.mu.Unlock()
}

// A JVM that stops being tracked (its pod no longer monitored) gets this
// agent's own unused copy removed too, on Run's goroutine.
func TestAttacherRemoveCleansUp(t *testing.T) {
	a, ops := newTestAttacher()
	clock := withClock(a)
	ctx := context.Background()
	attempt(t, a, hotspot())
	require.Equal(t, []string{testJarDir}, ops.keeps())

	a.Add(hotspot(), nil) // a second subscription for the pod
	a.Remove(hotspot().Key())
	a.runDue(ctx)
	assert.Len(t, ops.cleanups, 1, "removed while still tracked")

	a.Remove(hotspot().Key())
	assert.Len(t, ops.cleanups, 1, "removed on the caller's goroutine")
	a.runDue(ctx)
	require.Len(t, ops.cleanups, 2)
	assert.Equal(t, cleanupCall{"", clock.t.Add(-stagingGrace)}, ops.cleanups[1])

	// A queued look at young copies and the removal merge: at once, and
	// this agent's copy included.
	a, ops = newTestAttacher()
	clock = withClock(a)
	ops.cleanup = cleanupResult{young: []string{testJarDir}}
	attempt(t, a, hotspot())
	ops.cleanup = cleanupResult{}
	a.Remove(hotspot().Key())
	a.runDue(ctx)
	require.Len(t, ops.cleanups, 2)
	assert.Equal(t, "", ops.cleanups[1].keep)
	clock.advance(stagingGrace)
	a.runDue(ctx)
	assert.Len(t, ops.cleanups, 2, "looked twice")

	// It exited: nothing to remove from.
	a, ops = newTestAttacher()
	a.Add(hotspot(), nil)
	ops.dead = true
	a.Remove(hotspot().Key())
	a.runDue(ctx)
	assert.Empty(t, ops.cleanups)
}

// A failed removal is only logged.
func TestAttacherCleanupFails(t *testing.T) {
	a, ops := newTestAttacher()
	ops.cleanup = cleanupResult{removed: []string{"agent-1"}, held: map[string]uint32{"agent-2": 7}}
	ops.cleanupErr = errors.New("agent-3: busy")
	assert.True(t, attempt(t, a, hotspot()).done)
	assert.Equal(t, uint64(1), a.Stats().Attached)
}

// A probe that signalled counts as a signal for the whole attempt.
func TestAttacherProbeSignalNotRetried(t *testing.T) {
	a, ops := newTestAttacher()
	ops.result = attach.Result{Outcome: attach.Failed, Reason: attach.ReasonConnectFailed}
	assert.True(t, attempt(t, a, hotspot()).done, "retried after the probe's signal")

	a, ops = newTestAttacher()
	ops.stageErr = errors.New("read-only file system")
	assert.True(t, attempt(t, a, hotspot()).done, "retried after the probe's signal")
	assert.Equal(t, uint64(1), a.Stats().Failed[FailStage])
}

func TestJarVersion(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("META-INF/MANIFEST.MF")
	require.NoError(t, err)
	_, err = w.Write([]byte("Manifest-Version: 1.0\r\nImplementation-Version: 0.42.0-rc3\r\nAgent-Class: x\r\n\r\n"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	assert.Equal(t, "0.42.0-rc3", jarVersion(buf.Bytes()))
	assert.Equal(t, "", jarVersion([]byte("jar")))
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
	ops.probe = attach.Result{Outcome: attach.Failed, Reason: attach.ReasonConnectFailed}
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
	ops.probe = attach.Result{Outcome: attach.Failed, Reason: attach.ReasonConnectFailed, Signalled: true}
	s = attempt(t, a, hotspot())
	assert.True(t, s.done)

	// The helper did not report: it may have signalled, so never again.
	a, ops = newTestAttacher()
	ops.helper = errors.New("helper crashed")
	s = attempt(t, a, hotspot())
	assert.True(t, s.done)
	assert.Equal(t, uint64(1), a.Stats().Failed[FailHelper])
}

// A helper that fails on the attach after the probe, or on the retry after a
// load_failed, is a helper failure: it may have signalled, so never again.
func TestAttacherHelperFailsAfterStaging(t *testing.T) {
	a, ops := newTestAttacher()
	ops.attachErrs = []error{errors.New("helper timed out")}
	s := attempt(t, a, hotspot())
	assert.True(t, s.done)
	assert.Equal(t, 1, ops.staged)
	assert.Equal(t, uint64(1), a.Stats().Failed[FailHelper])

	a, ops = newTestAttacher()
	ops.results = []attach.Result{{Outcome: attach.Failed, Reason: attach.ReasonLoadFailed, Detail: "agent returned 100"}}
	ops.attachErrs = []error{nil, errors.New("invalid JSON from the helper")}
	s = attempt(t, a, hotspot())
	assert.True(t, s.done)
	assert.Equal(t, 2, ops.staged)
	assert.Len(t, ops.requests, 3)
	assert.Equal(t, uint64(1), a.Stats().Failed[FailHelper])
	assert.Zero(t, a.Stats().Failed[attach.ReasonLoadFailed])
}

func TestAttacherRetriesStagingAndInspection(t *testing.T) {
	a, ops := newTestAttacher()
	ops.probe.Signalled = false
	ops.stageErr = errors.New("read-only file system")
	s := attempt(t, a, hotspot())
	assert.False(t, s.done)
	assert.Len(t, ops.requests, 1, "attached without a jar")

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
	a.Add(hotspot(), nil)
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

// recorder collects the telemetry events reported for a JVM.
type recorder struct{ events []string }

func (r *recorder) report(event string) { r.events = append(r.events, event) }

func TestAttacherReportsEvents(t *testing.T) {
	run := func(setup func(*fakeOps), p *Process) []string {
		a, ops := newTestAttacher()
		setup(ops)
		var rec recorder
		a.Add(p, rec.report)
		for s := a.next(time.Now().Add(time.Hour)); s != nil; s = a.next(time.Now().Add(time.Hour)) {
			a.try(context.Background(), s)
		}
		return rec.events
	}
	openj9 := hotspot()
	openj9.Kind = OpenJ9

	assert.Equal(t, []string{EventAttached}, run(func(*fakeOps) {}, hotspot()))
	assert.Equal(t, []string{EventSkippedPrefix + SkipOpenJ9}, run(func(*fakeOps) {}, openj9))
	assert.Equal(t, []string{EventAlreadyRunning}, run(func(o *fakeOps) {
		o.info.args = []string{"-javaagent:/opt/postman/postman-insights-java-agent.jar"}
	}, hotspot()))
	assert.Equal(t, []string{EventAlreadyRunning}, run(func(o *fakeOps) {
		o.probe = attach.Result{Outcome: attach.AlreadyLoaded, AgentVersion: "0.9.0"}
	}, hotspot()))
	assert.Equal(t, []string{EventSkippedPrefix + attach.ReasonNoListener}, run(func(o *fakeOps) {
		o.info.sigQuitCaught = false
		o.probe = attach.Result{Outcome: attach.Failed, Reason: attach.ReasonNoListener}
	}, hotspot()))
	// Retries report nothing; only the final failure does.
	assert.Equal(t, []string{EventFailedPrefix + attach.ReasonConnectFailed}, run(func(o *fakeOps) {
		o.probe = attach.Result{Outcome: attach.Failed, Reason: attach.ReasonConnectFailed}
	}, hotspot()))
}

func TestAttacherCountsAdds(t *testing.T) {
	a, ops := newTestAttacher()
	ops.info.age = time.Second // not attached yet
	var older, newer recorder
	a.Add(hotspot(), older.report)
	a.Add(hotspot(), newer.report) // a second subscription for the pod
	assert.Equal(t, uint64(1), a.Stats().Seen)

	// The older subscription goes away; the JVM stays queued, and reports
	// to the newer one.
	a.Remove(hotspot().Key())
	ops.info.age = time.Minute
	s := a.next(time.Now())
	require.NotNil(t, s)
	a.try(context.Background(), s)
	assert.Empty(t, older.events)
	assert.Equal(t, []string{EventAttached}, newer.events)

	a.Remove(hotspot().Key())
	a.mu.Lock()
	assert.Empty(t, a.jvms)
	a.mu.Unlock()
}
