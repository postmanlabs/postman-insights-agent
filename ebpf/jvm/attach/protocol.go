// Package attach loads the Java agent into a running HotSpot JVM. It is the
// code of the postman-insights-jvm-attach helper
// (cmd/postman-insights-jvm-attach), which the Insights agent runs as the
// JVM's own user: HotSpot accepts attach requests only from that user, and
// the Insights agent cannot change its own user without dropping root for all
// its threads.
//
// The Insights agent makes every decision (which JVMs, whether a signal is
// allowed) and stages the jar. The helper does what only the JVM's user can
// do: it reads the JVM's files that only that user may read (its perf data
// and environment, OpInspect), so the Insights agent needs no capability
// that bypasses file permissions, and it performs the attach (OpAttach). The
// two talk through Request on stdin and Result on stdout.
package attach

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// RequestVersion1 is the only Request format so far. The helper and the
// Insights agent ship in the same image, but a version still lets the helper
// refuse a request it does not understand rather than guess.
const RequestVersion1 = 1

// Ops a Request can ask for.
const (
	// OpInspect reads what the Insights agent checks before attaching (see
	// Inspection).
	OpInspect = "inspect"
	// OpAttach loads the agent.
	OpAttach = "attach"
)

// Request is what the Insights agent asks the helper to do.
type Request struct {
	Version int    `json:"version"`
	Op      string `json:"op"`
	// ProcRoot, PID and StartTime identify the JVM: the helper acts only on
	// the process with that PID and start time.
	ProcRoot  string `json:"proc_root"`
	PID       uint32 `json:"pid"`
	StartTime uint64 `json:"start_time"`
	// NSPID is the JVM's PID in its own namespace, which its attach and
	// perf data files are named after.
	NSPID uint32 `json:"nspid"`
	// JarPath is the agent jar's path inside the JVM's container, and
	// AgentArgs the agent's arguments (OpAttach).
	JarPath   string `json:"jar_path,omitempty"`
	AgentArgs string `json:"agent_args,omitempty"`
	// AllowSignal permits starting the JVM's attach listener with SIGQUIT
	// when it is not running yet (OpAttach). The Insights agent sets it only
	// when the JVM catches SIGQUIT and has attach enabled; otherwise the
	// signal would kill the JVM or dump its threads into the application's
	// log.
	AllowSignal bool `json:"allow_signal,omitempty"`
}

// Outcome is what an attach request ended in.
type Outcome string

const (
	// Attached: the agent was loaded and reports itself running.
	Attached Outcome = "attached"
	// AlreadyLoaded: the agent was already running in the JVM (loaded at
	// start with -javaagent, or by an earlier attach); nothing was loaded.
	AlreadyLoaded Outcome = "already_loaded"
	// Inspected: Result.Inspection holds what OpInspect read.
	Inspected Outcome = "inspected"
	// Failed: see Result.Reason.
	Failed Outcome = "failed"
)

// Failure reasons, for logs and telemetry.
const (
	ReasonBadRequest      = "bad_request"
	ReasonProcessGone     = "process_gone"
	ReasonInspectFailed   = "inspect_failed"     // OpInspect could not read the JVM's files
	ReasonNoListener      = "no_attach_listener" // not running, and no signal allowed
	ReasonSignalFailed    = "signal_failed"
	ReasonListenerTimeout = "attach_listener_timeout" // signalled, but no listener appeared
	// ReasonAttachInProgress: another attach owned the trigger file, and
	// its listener did not come up in time. Not signalled; worth a retry.
	ReasonAttachInProgress = "attach_in_progress"
	ReasonConnectFailed    = "connect_failed"
	ReasonProtocol         = "protocol_error"
	ReasonLoadFailed       = "load_failed"  // the JVM refused to load the agent
	ReasonAgentFailed      = "agent_failed" // the agent loaded but failed to start
	ReasonEarlierFailure   = "agent_failed_earlier"
)

// Result is what the helper reports.
type Result struct {
	Outcome Outcome `json:"outcome"`
	// Reason is one of the Reason constants when Outcome is Failed.
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
	// Signalled reports that the helper sent SIGQUIT. A JVM is never
	// signalled twice, so a failure after a signal is never retried.
	Signalled bool `json:"signalled,omitempty"`
	// AgentVersion is the running agent's version, when one is running.
	AgentVersion string `json:"agent_version,omitempty"`
	// Inspection is OpInspect's result, when Outcome is Inspected.
	Inspection *Inspection `json:"inspection,omitempty"`
}

// Inspection is what the Insights agent checks before attaching that only the
// JVM's user may read.
type Inspection struct {
	// PerfData holds the PerfDataKeys entries of the JVM's perf data file
	// (/tmp/hsperfdata_<user>/<nspid>), when the JVM publishes one that has
	// its effective arguments (java.rt.vmArgs).
	PerfData map[string]string `json:"perf_data,omitempty"`
	// JavaOptions holds the JavaOptionVars set in the JVM's environment.
	// It is read only without perf data, whose arguments include them.
	JavaOptions map[string]string `json:"java_options,omitempty"`
}

// PerfDataKeys are the perf data entries an Inspection reports: the JVM's
// effective arguments and flags, and its capabilities (whether attach is on).
var PerfDataKeys = []string{"java.rt.vmArgs", "java.rt.vmFlags", "sun.rt.jvmCapabilities"}

// JavaOptionVars are the environment variables HotSpot and the java launcher
// read options from.
var JavaOptionVars = []string{"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"}

func failed(reason string, signalled bool, format string, a ...any) Result {
	return Result{Outcome: Failed, Reason: reason, Signalled: signalled, Detail: fmt.Sprintf(format, a...)}
}

// HotSpot's attach protocol, version 1: the client sends "1", a command and
// exactly three arguments, each NUL-terminated. The JVM answers with a status
// line (0 for success) followed by the command's output, and closes.
const protocolVersion = "1"

// errStatus is a non-zero status from the JVM, with its message.
type errStatus struct {
	code int
	msg  string
}

func (e *errStatus) Error() string {
	return fmt.Sprintf("status %d: %s", e.code, strings.TrimSpace(e.msg))
}

// execute sends one command over the attach socket at sock and returns its
// output.
func execute(sock string, timeout time.Duration, cmd string, args ...string) (string, error) {
	if len(args) > 3 {
		return "", errors.New("at most three arguments")
	}
	conn, err := net.DialTimeout("unix", sock, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	return roundTrip(conn, cmd, args...)
}

func roundTrip(conn io.ReadWriter, cmd string, args ...string) (string, error) {
	var b strings.Builder
	for _, part := range []string{protocolVersion, cmd} {
		b.WriteString(part)
		b.WriteByte(0)
	}
	for i := range 3 {
		if i < len(args) {
			b.WriteString(args[i])
		}
		b.WriteByte(0)
	}
	if _, err := io.WriteString(conn, b.String()); err != nil {
		return "", err
	}
	r := bufio.NewReader(conn)
	statusLine, err := r.ReadString('\n')
	if err != nil && statusLine == "" {
		return "", fmt.Errorf("no reply: %w", err)
	}
	code, err := strconv.Atoi(strings.TrimSpace(statusLine))
	if err != nil {
		return "", fmt.Errorf("bad status line %q", statusLine)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", &errStatus{code, string(out)}
	}
	return string(out), nil
}

// loadResult interprets the output of "load instrument": the agent's return
// code, as "return code: N" on JDK 9+ and as a bare number on JDK 8.
func loadResult(out string) error {
	s := strings.TrimSpace(out)
	if s == "" {
		return errors.New("no reply to load")
	}
	if n, ok := strings.CutPrefix(s, "return code: "); ok {
		s = n
	}
	code, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("unexpected reply to load: %q", out)
	}
	if code != 0 {
		return fmt.Errorf("agent returned %d", code)
	}
	return nil
}

// property returns a system property from the output of "properties"
// (java.util.Properties.store format), or "" when it is not set. Keys are
// compared as stored; the agent's are plain dotted names.
func property(out, key string) string {
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return unescapeProperty(v)
		}
	}
	return ""
}

// unescapeProperty undoes the escapes Properties.store writes in values.
func unescapeProperty(v string) string {
	if !strings.Contains(v, `\`) {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c != '\\' || i+1 == len(v) {
			b.WriteByte(c)
			continue
		}
		i++
		switch v[i] {
		case 't':
			b.WriteByte('\t')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 'f':
			b.WriteByte('\f')
		case 'u':
			if i+4 < len(v) {
				if r, err := strconv.ParseUint(v[i+1:i+5], 16, 16); err == nil {
					b.WriteRune(rune(r))
					i += 4
					continue
				}
			}
			b.WriteByte('u')
		default:
			b.WriteByte(v[i])
		}
	}
	return b.String()
}
