// SPDX-License-Identifier: Apache-2.0

package jvm

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/postmanlabs/postman-insights-agent/ebpf/jvm/attach"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// Attacher loads the Java agent into the running JVMs it is given, so their
// HTTPS traffic is captured with no change to their pods and no restart. It
// works through the postman-insights-jvm-attach helper, which it runs as each
// JVM's own user to read the JVM's files that only that user may read and to
// attach; it decides everything itself, as root.
//
// It never attaches twice: a JVM that already runs the agent (loaded at
// start with -javaagent, or attached before this Insights agent restarted)
// is left alone. It never signals a JVM that would not handle the signal as
// an attach request, and never signals one JVM twice, because a stray
// SIGQUIT makes a JVM print a thread dump into the application's log.
//
// It copies the jar into a JVM's container only when the JVM does not run
// the agent yet. Once an attempt is over (the JVM runs the agent, or the
// attach failed for good), it removes the copies other Insights agent
// versions left there, and when a JVM stops being tracked, its own copy too;
// never one that a process still has open or mapped, or that was staged less
// than stagingGrace ago (see removeStaleCopies).
//
// Safe for concurrent use. Attaches and removals run one at a time, on Run's
// goroutine.
type Attacher struct {
	ops       attachOps
	jar       []byte
	jarDir    string // staging directory name, from the jar's checksum
	version   string // the jar's Implementation-Version, or "" when unknown
	agentArgs func() string

	// now is the clock, time.Now outside tests.
	now func() time.Time

	mu    sync.Mutex
	jvms  map[Key]*attachState
	stats AttachStats
	// cleanups holds the removals of copies to run, one per JVM whose
	// container they are in.
	cleanups map[Key]*cleanupJob
	// wake nudges Run when a JVM is added or a removal is due.
	wake chan struct{}
}

// cleanupJob is a removal of copies from p's container, due at due.
type cleanupJob struct {
	p   *Process
	due time.Time
	// keep is the staging directory to keep, or "" to remove this agent's
	// own copy too.
	keep string
}

// AttacherConfig configures an Attacher.
type AttacherConfig struct {
	// HelperPath is the postman-insights-jvm-attach binary.
	HelperPath string
	// JarPath and ChecksumPath are the agent jar and its SHA-256, in
	// sha256sum format.
	JarPath, ChecksumPath string
	// AgentArgs returns the agent's arguments for the next attach.
	AgentArgs func() string
}

// AttachStats counts what happened to the JVMs given to an Attacher.
type AttachStats struct {
	// Seen counts JVMs added.
	Seen uint64
	// Attached counts JVMs the agent was loaded into.
	Attached uint64
	// AlreadyRunning counts JVMs that already ran the agent: loaded at
	// start (-javaagent) or by an earlier attach.
	AlreadyRunning uint64
	// OtherVersion counts the AlreadyRunning JVMs attached earlier with
	// another version of the agent than this Insights agent's. A loaded
	// agent cannot be replaced, so they run that version until they
	// restart.
	OtherVersion uint64
	// Skipped and Failed count JVMs not attached, by reason.
	Skipped map[string]uint64
	Failed  map[string]uint64
}

// Reasons a JVM is not attached, besides the helper's (attach.Reason*).
const (
	SkipOpenJ9                 = "openj9"
	SkipAttachDisabled         = "attach_disabled"
	SkipDynamicLoadingDisabled = "dynamic_loading_disabled"
	FailInspect                = "inspect_failed"
	FailStage                  = "stage_failed"
	FailHelper                 = "helper_failed"
)

// Telemetry events, one per JVM and outcome. The Attacher gives the outcome
// events to the report function passed to Add; EventSeen is for whoever
// discovers JVMs, which happens whether or not they can be attached.
const (
	EventSeen           = "java_jvm_seen"
	EventAttached       = "java_jvm_attached"
	EventAlreadyRunning = "java_jvm_agent_already_running"
	// EventSkippedPrefix and EventFailedPrefix are followed by the reason
	// (Skip*, Fail* or attach.Reason*).
	EventSkippedPrefix = "java_jvm_attach_skipped_"
	EventFailedPrefix  = "java_jvm_attach_failed_"
)

// attachOps is everything the Attacher does to real processes, so the
// decisions can be tested without JVMs.
type attachOps interface {
	alive(p *Process) bool
	inspect(ctx context.Context, p *Process) (gateInfo, error)
	// stage copies jar into p's container, in the staging directory
	// dirName, and sets its modification time to now.
	stage(p *Process, jar []byte, dirName string, now time.Time) (string, error)
	// attach runs the helper for an OpProbe or OpAttach request.
	attach(ctx context.Context, p *Process, req attach.Request) (attach.Result, error)
	// removeStaleCopies removes the jar copies other than keep (all of them
	// when keep is "") from p's container, except those still in use and
	// those modified after youngAfter.
	removeStaleCopies(p *Process, keep string, youngAfter time.Time) (cleanupResult, error)
}

// cleanupResult is what removeStaleCopies did, by staging directory name.
type cleanupResult struct {
	removed []string
	// held maps each copy kept because a process has one of its files open
	// or mapped to one such process.
	held map[string]uint32
	// young lists the copies kept because they were staged or reused less
	// than stagingGrace ago.
	young []string
}

// stagingGrace is how long a copy is kept after it was staged or reused, so
// an attach in progress, this agent's or another Insights agent's on the same
// node, never loses its copy before the JVM maps it. It is several times
// the longest attach run (attachTimeout), and a copy kept for being younger
// is looked at again once it is older.
const stagingGrace = 10 * time.Minute

// gateInfo is what the Attacher checks before attaching.
type gateInfo struct {
	// age is how long the JVM has been running.
	age time.Duration
	// args are its effective arguments, and argsSource where they came
	// from.
	args       []string
	argsSource string
	// attachOn is whether the JVM's attach mechanism is on, when the JVM
	// says so itself (attachKnown, from its perf data); otherwise its
	// arguments tell.
	attachOn, attachKnown bool
	// sigQuitCaught: the JVM handles SIGQUIT (no -Xrs).
	sigQuitCaught bool
}

// minAge is how long a JVM must have run before it is attached, so the attach
// does not race its start-up.
const minAge = 5 * time.Second

// retryDelays are the waits before retrying an attach that failed without a
// signal. Failures after a signal are never retried.
var retryDelays = []time.Duration{30 * time.Second, 2 * time.Minute, 10 * time.Minute}

type attachState struct {
	p        *Process
	due      time.Time
	attempts int
	done     bool
	// refs counts the callers that added p: two subscriptions can cover the
	// same pod while one replaces the other.
	refs int
	// report receives the JVM's telemetry events; it is the latest caller's,
	// which outlives the subscription it replaces. May be nil.
	report func(event string)
}

// NewAttacher reads the agent jar and checks it against its checksum.
func NewAttacher(cfg AttacherConfig) (*Attacher, error) {
	if _, err := os.Stat(cfg.HelperPath); err != nil {
		return nil, fmt.Errorf("attach helper: %w", err)
	}
	jar, err := os.ReadFile(cfg.JarPath)
	if err != nil {
		return nil, err
	}
	sums, err := os.ReadFile(cfg.ChecksumPath)
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(sums))
	if len(fields) == 0 {
		return nil, fmt.Errorf("%s: no checksum", cfg.ChecksumPath)
	}
	want := fields[0]
	sum := sha256.Sum256(jar)
	got := hex.EncodeToString(sum[:])
	if got != want {
		return nil, fmt.Errorf("%s: SHA-256 %s, but %s says %s", cfg.JarPath, got, cfg.ChecksumPath, want)
	}
	ops, err := platformOps(cfg.HelperPath)
	if err != nil {
		return nil, err
	}
	a := newAttacher(ops, jar, got, cfg.AgentArgs)
	a.version = jarVersion(jar)
	return a, nil
}

// jarVersion returns the Implementation-Version in jar's manifest, or "".
func jarVersion(jar []byte) string {
	zr, err := zip.NewReader(bytes.NewReader(jar), int64(len(jar)))
	if err != nil {
		return ""
	}
	f, err := zr.Open("META-INF/MANIFEST.MF")
	if err != nil {
		return ""
	}
	defer f.Close()
	manifest, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(manifest), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimRight(line, "\r"), "Implementation-Version:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func newAttacher(ops attachOps, jar []byte, sum string, agentArgs func() string) *Attacher {
	return &Attacher{
		ops: ops,
		jar: jar,
		// The checksum names the directory, so Insights agents with
		// different jars never share one, and the same jar is staged once.
		jarDir:    "agent-" + sum[:16],
		agentArgs: agentArgs,
		now:       time.Now,
		jvms:      make(map[Key]*attachState),
		stats:     AttachStats{Skipped: map[string]uint64{}, Failed: map[string]uint64{}},
		cleanups:  make(map[Key]*cleanupJob),
		wake:      make(chan struct{}, 1),
	}
}

// Add queues p for attaching. report, when not nil, receives one telemetry
// event for what happened to it (EventAttached, EventAlreadyRunning, or an
// EventSkippedPrefix or EventFailedPrefix event). Adding a JVM again attaches
// nothing more; it only takes over reporting.
func (a *Attacher) Add(p *Process, report func(event string)) {
	a.mu.Lock()
	if s, ok := a.jvms[p.Key()]; ok {
		s.refs++
		if report != nil {
			s.report = report
		}
		a.mu.Unlock()
		return
	}
	a.jvms[p.Key()] = &attachState{p: p, due: a.now(), refs: 1, report: report}
	a.stats.Seen++
	a.nudge()
	a.mu.Unlock()
}

// nudge wakes Run.
func (a *Attacher) nudge() {
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

// Remove undoes one Add. After the last, it forgets the JVM, and removes the
// unused copies from its container, this agent's own included: its pod is no
// longer monitored, or Java capture is off for it. Run does the removal,
// which skips JVMs that exited.
func (a *Attacher) Remove(k Key) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if s, ok := a.jvms[k]; ok {
		if s.refs--; s.refs <= 0 {
			delete(a.jvms, k)
			a.scheduleCleanupLocked(s.p, "", a.now())
			a.nudge()
		}
	}
}

// scheduleCleanupLocked queues a removal of copies from p's container at due.
// A removal already queued for p is merged with it: it runs at the earlier
// time, and keeps this agent's copy only if both would. Caller holds mu.
func (a *Attacher) scheduleCleanupLocked(p *Process, keep string, due time.Time) {
	j, ok := a.cleanups[p.Key()]
	if !ok {
		a.cleanups[p.Key()] = &cleanupJob{p: p, due: due, keep: keep}
		return
	}
	if due.Before(j.due) {
		j.due = due
	}
	if keep == "" {
		j.keep = ""
	}
}

// forget drops a JVM that exited.
func (a *Attacher) forget(k Key) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.jvms, k)
}

// Stats returns a copy of the counters.
func (a *Attacher) Stats() AttachStats {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.stats
	s.Skipped, s.Failed = copyCounts(s.Skipped), copyCounts(s.Failed)
	return s
}

func copyCounts(m map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Run attaches due JVMs and removes copies when due, one at a time, until
// ctx ends.
func (a *Attacher) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-a.wake:
		}
		a.runDue(ctx)
	}
}

// runDue makes the attach attempts and removals that are due, until none is
// or ctx ends.
func (a *Attacher) runDue(ctx context.Context) {
	for ctx.Err() == nil {
		now := a.now()
		if s := a.next(now); s != nil {
			a.try(ctx, s)
		} else if j := a.nextCleanup(now); j != nil {
			a.runCleanup(j)
		} else {
			return
		}
	}
}

// nextCleanup takes a due removal off the queue, or returns nil.
func (a *Attacher) nextCleanup(now time.Time) *cleanupJob {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, j := range a.cleanups {
		if !j.due.After(now) {
			delete(a.cleanups, k)
			return j
		}
	}
	return nil
}

// runCleanup runs a queued removal, if its JVM still runs: once it has
// exited, its container may be gone, and nothing else here can reach it.
func (a *Attacher) runCleanup(j *cleanupJob) {
	if !a.ops.alive(j.p) {
		return
	}
	a.removeStaleCopies(j.p, j.keep)
}

// next returns a JVM whose attach is due, or nil.
func (a *Attacher) next(now time.Time) *attachState {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range a.jvms {
		if !s.done && !s.due.After(now) {
			return s
		}
	}
	return nil
}

// try makes one attach attempt and records the outcome.
func (a *Attacher) try(ctx context.Context, s *attachState) {
	p := s.p
	if !a.ops.alive(p) {
		a.forget(p.Key())
		return
	}
	if p.Kind != HotSpot {
		a.skip(s, SkipOpenJ9, "an OpenJ9 JVM; start it with -javaagent to capture its HTTPS traffic")
		return
	}
	info, err := a.ops.inspect(ctx, p)
	if err != nil {
		a.fail(s, FailInspect, false, err.Error())
		return
	}
	if info.age < minAge {
		a.reschedule(s, a.now().Add(minAge-info.age))
		return
	}
	flags := parseFlags(info.args)
	if info.attachKnown {
		flags.attachDisabled = !info.attachOn
	}
	switch {
	case flags.attachDisabled:
		a.skip(s, SkipAttachDisabled, "attach is disabled (-XX:+DisableAttachMechanism, from its "+info.argsSource+")")
		return
	case flags.dynamicLoadingDisabled:
		a.skip(s, SkipDynamicLoadingDisabled, "dynamic agent loading is disabled (-XX:-EnableDynamicAgentLoading)")
		return
	case flags.staticAgent:
		a.finish(s, EventAlreadyRunning, func(st *AttachStats) { st.AlreadyRunning++ },
			"ebpf: Java agent already loaded at start (-javaagent) in JVM %s\n", p)
		a.removeStaleCopies(p, a.jarDir)
		return
	}

	start := a.now()
	req := attach.Request{
		Version:     attach.RequestVersion1,
		Op:          attach.OpProbe,
		ProcRoot:    p.ProcRoot,
		PID:         p.PID,
		StartTime:   p.StartTime,
		NSPID:       p.NSPID,
		AllowSignal: info.sigQuitCaught,
	}
	res, err := a.ops.attach(ctx, p, req)
	if err == nil && res.Outcome == attach.NotLoaded {
		// The jar is copied into the container only now, so a JVM that
		// runs the agent already gets no copy it would never load.
		// Assigned, not declared: the attach errors below must reach the
		// helper-error handling after this block.
		var jarPath string
		jarPath, err = a.ops.stage(p, a.jar, a.jarDir, a.now())
		if err != nil {
			a.fail(s, FailStage, res.Signalled, err.Error())
			return
		}
		signalled := res.Signalled
		req.Op, req.JarPath, req.AgentArgs = attach.OpAttach, jarPath, a.agentArgs()
		// The probe started the listener; a JVM is never signalled twice.
		req.AllowSignal = req.AllowSignal && !signalled
		res, err = a.ops.attach(ctx, p, req)
		res.Signalled = res.Signalled || signalled
		if err == nil && jarMayHaveGone(res) {
			// The copy may have been removed before the JVM loaded it, by
			// an Insights agent that does not keep young copies (one from
			// before stagingGrace). Nothing was loaded, so stage it again
			// and attach once more. The listener runs now: no signal.
			printer.Stderr.Warningf("ebpf: Java agent not attached to JVM %s (%s: %s); staging its copy again and retrying once\n",
				p, res.Reason, res.Detail)
			signalled = res.Signalled
			if req.JarPath, err = a.ops.stage(p, a.jar, a.jarDir, a.now()); err != nil {
				a.fail(s, FailStage, signalled, err.Error())
				return
			}
			req.AllowSignal = false
			res, err = a.ops.attach(ctx, p, req)
			res.Signalled = res.Signalled || signalled
		}
	}
	if err != nil {
		// The helper did not report, so whether it signalled is unknown:
		// assume it did, and never retry.
		a.fail(s, FailHelper, true, err.Error())
		return
	}
	switch res.Outcome {
	case attach.Attached:
		how := "its attach listener was already running"
		if res.Signalled {
			how = "started its attach listener with SIGQUIT"
		}
		a.finish(s, EventAttached, func(st *AttachStats) { st.Attached++ },
			"ebpf: Java agent %s attached to JVM %s in %d ms (%s)\n",
			res.AgentVersion, p, a.now().Sub(start).Milliseconds(), how)
		a.removeStaleCopies(p, a.jarDir)
	case attach.AlreadyLoaded:
		if a.version != "" && res.AgentVersion != a.version {
			a.finish(s, EventAlreadyRunning, func(st *AttachStats) { st.AlreadyRunning++; st.OtherVersion++ },
				"ebpf: Java agent %s already running in JVM %s; this Insights agent's Java agent %s replaces it only when the JVM restarts\n",
				res.AgentVersion, p, a.version)
		} else {
			a.finish(s, EventAlreadyRunning, func(st *AttachStats) { st.AlreadyRunning++ },
				"ebpf: Java agent %s already running in JVM %s\n", res.AgentVersion, p)
		}
		a.removeStaleCopies(p, a.jarDir)
	case attach.NotLoaded:
		// Only a probe reports it, and a probe that does is followed by
		// an attach.
		a.fail(s, attach.ReasonProtocol, res.Signalled, "the helper reported not_loaded to an attach")
	default:
		if res.Reason == attach.ReasonNoListener {
			a.skip(s, res.Reason, "its attach listener is not running and it ignores SIGQUIT (-Xrs)")
			return
		}
		a.fail(s, res.Reason, res.Signalled, res.Detail)
	}
}

// jarMayHaveGone reports whether an attach failed in a way that a missing
// copy explains, and that loaded nothing: the JVM could not load the jar, or
// the agent could not open it and started nothing.
func jarMayHaveGone(res attach.Result) bool {
	return res.Outcome == attach.Failed &&
		(res.Reason == attach.ReasonLoadFailed || res.Reason == attach.ReasonAgentNotStarted)
}

// removeStaleCopies removes the unused jar copies other Insights agent
// versions left in p's container, and this agent's own too when keep is "".
// Copies in use are kept, and so are copies staged or reused less than
// stagingGrace ago, whose removal is queued again for when they are older.
//
// It runs once an attempt is over, whatever its outcome: copies are removed
// by what holds them and how old they are, not by what the JVM runs.
func (a *Attacher) removeStaleCopies(p *Process, keep string) {
	now := a.now()
	res, err := a.ops.removeStaleCopies(p, keep, now.Add(-stagingGrace))
	if len(res.removed) > 0 {
		printer.Stderr.Infof("ebpf: removed unused Java agent copies %s from the container of JVM %s\n",
			strings.Join(res.removed, ", "), p)
	}
	for dir, pid := range res.held {
		printer.Stderr.Debugf("ebpf: kept Java agent copy %s in the container of JVM %s: in use by pid %d\n", dir, p, pid)
	}
	if len(res.young) > 0 {
		printer.Stderr.Debugf("ebpf: kept Java agent copies %s in the container of JVM %s: staged less than %s ago; looking again then\n",
			strings.Join(res.young, ", "), p, stagingGrace)
		a.mu.Lock()
		a.scheduleCleanupLocked(p, keep, now.Add(stagingGrace))
		a.mu.Unlock()
	}
	if err != nil {
		printer.Stderr.Warningf("ebpf: could not remove unused Java agent copies from the container of JVM %s: %v\n", p, err)
	}
}

// finish records the JVM's outcome: it counts it, reports event and logs.
func (a *Attacher) finish(s *attachState, event string, count func(*AttachStats), format string, args ...any) {
	a.mu.Lock()
	s.done = true
	count(&a.stats)
	report := s.report
	a.mu.Unlock()
	if report != nil {
		report(event)
	}
	printer.Stderr.Infof(format, args...)
}

func (a *Attacher) skip(s *attachState, reason, why string) {
	a.finish(s, EventSkippedPrefix+reason, func(st *AttachStats) { st.Skipped[reason]++ },
		"ebpf: Java agent not attached to JVM %s: %s\n", s.p, why)
}

func (a *Attacher) reschedule(s *attachState, due time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s.due = due
}

// fail records a failed attempt, and retries later when no signal was sent.
// A failure for good also removes unused copies from the JVM's container.
func (a *Attacher) fail(s *attachState, reason string, signalled bool, detail string) {
	retry := !signalled && retryable(reason) && s.attempts < len(retryDelays)
	a.mu.Lock()
	if retry {
		s.due = a.now().Add(retryDelays[s.attempts])
		s.attempts++
	} else {
		s.done = true
		a.stats.Failed[reason]++
	}
	report := s.report
	a.mu.Unlock()

	if retry {
		printer.Stderr.Warningf("ebpf: Java agent not attached to JVM %s yet (%s: %s); retrying in %s\n",
			s.p, reason, detail, retryDelays[s.attempts-1])
		return
	}
	if report != nil {
		report(EventFailedPrefix + reason)
	}
	never := ""
	if signalled {
		never = "; it was signalled once, so it is not retried"
	}
	printer.Stderr.Warningf("ebpf: Java agent not attached to JVM %s (%s: %s)%s\n", s.p, reason, detail, never)
	if a.ops.alive(s.p) {
		a.removeStaleCopies(s.p, a.jarDir)
	}
}

// retryable reports whether a failure may go away by itself.
func retryable(reason string) bool {
	switch reason {
	case FailInspect, FailStage, attach.ReasonConnectFailed, attach.ReasonProtocol, attach.ReasonAttachInProgress:
		return true
	}
	return false
}

// errAttachUnsupported is returned by NewAttacher where attach is not
// supported.
var errAttachUnsupported = errors.New("jvm: attach is only supported on Linux")
