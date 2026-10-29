package jvm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
// Safe for concurrent use. Attaches run one at a time, on Run's goroutine.
type Attacher struct {
	ops       attachOps
	jar       []byte
	jarDir    string // staging directory name, from the jar's checksum
	agentArgs func() string

	mu    sync.Mutex
	jvms  map[Key]*attachState
	stats AttachStats
	// wake nudges Run when a JVM is added.
	wake chan struct{}
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
	stage(p *Process, jar []byte, dirName string) (string, error)
	attach(ctx context.Context, p *Process, req attach.Request) (attach.Result, error)
}

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
	return newAttacher(ops, jar, got, cfg.AgentArgs), nil
}

func newAttacher(ops attachOps, jar []byte, sum string, agentArgs func() string) *Attacher {
	return &Attacher{
		ops: ops,
		jar: jar,
		// The checksum names the directory, so Insights agents with
		// different jars never share one, and the same jar is staged once.
		jarDir:    "agent-" + sum[:16],
		agentArgs: agentArgs,
		jvms:      make(map[Key]*attachState),
		stats:     AttachStats{Skipped: map[string]uint64{}, Failed: map[string]uint64{}},
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
	a.jvms[p.Key()] = &attachState{p: p, due: time.Now(), refs: 1, report: report}
	a.stats.Seen++
	select {
	case a.wake <- struct{}{}:
	default:
	}
	a.mu.Unlock()
}

// Remove undoes one Add, and forgets the JVM after the last.
func (a *Attacher) Remove(k Key) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if s, ok := a.jvms[k]; ok {
		if s.refs--; s.refs <= 0 {
			delete(a.jvms, k)
		}
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

// Run attaches due JVMs, one at a time, until ctx ends.
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
		for {
			s := a.next(time.Now())
			if s == nil || ctx.Err() != nil {
				break
			}
			a.try(ctx, s)
		}
	}
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
		a.reschedule(s, time.Now().Add(minAge-info.age))
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
		return
	}

	jarPath, err := a.ops.stage(p, a.jar, a.jarDir)
	if err != nil {
		a.fail(s, FailStage, false, err.Error())
		return
	}
	start := time.Now()
	res, err := a.ops.attach(ctx, p, attach.Request{
		Version:     attach.RequestVersion1,
		Op:          attach.OpAttach,
		ProcRoot:    p.ProcRoot,
		PID:         p.PID,
		StartTime:   p.StartTime,
		NSPID:       p.NSPID,
		JarPath:     jarPath,
		AgentArgs:   a.agentArgs(),
		AllowSignal: info.sigQuitCaught,
	})
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
			res.AgentVersion, p, time.Since(start).Milliseconds(), how)
	case attach.AlreadyLoaded:
		a.finish(s, EventAlreadyRunning, func(st *AttachStats) { st.AlreadyRunning++ },
			"ebpf: Java agent %s already running in JVM %s\n", res.AgentVersion, p)
	default:
		if res.Reason == attach.ReasonNoListener {
			a.skip(s, res.Reason, "its attach listener is not running and it ignores SIGQUIT (-Xrs)")
			return
		}
		a.fail(s, res.Reason, res.Signalled, res.Detail)
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
func (a *Attacher) fail(s *attachState, reason string, signalled bool, detail string) {
	retry := !signalled && retryable(reason) && s.attempts < len(retryDelays)
	a.mu.Lock()
	if retry {
		s.due = time.Now().Add(retryDelays[s.attempts])
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
