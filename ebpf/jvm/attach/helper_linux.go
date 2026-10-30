//go:build linux

package attach

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"github.com/postmanlabs/postman-insights-agent/ebpf/javatls"
)

// Timeouts for each step. Loading takes longest: the agent installs its
// hooks before the JVM answers (0.3 to 0.5 s in the spike, more on a busy
// JVM).
const (
	listenerTimeout = 10 * time.Second
	queryTimeout    = 10 * time.Second
	loadTimeout     = 60 * time.Second
)

// staleTriggerAge is when a trigger file left by another attach is taken
// over: its creator removes it within listenerTimeout, unless it was killed.
const staleTriggerAge = 3 * listenerTimeout

// Run performs req and reports the outcome. It must run as the JVM's user.
func Run(req Request) Result {
	if req.Version != RequestVersion1 || req.PID == 0 || req.NSPID == 0 ||
		(req.Op != OpInspect && req.Op != OpProbe && req.Op != OpAttach) || (req.Op == OpAttach && req.JarPath == "") {
		return failed(ReasonBadRequest, false, "unsupported or incomplete request")
	}
	procDir := filepath.Join(req.ProcRoot, strconv.FormatUint(uint64(req.PID), 10))

	// The open /proc/<pid> directory refers to this process for as long as
	// it is open, even if the PID is reused, and the signal is sent through
	// it. That also works when ProcRoot is another PID namespace's /proc
	// (the node's, in kind), where a plain kill(pid) would hit the wrong
	// process.
	pidfd, err := unix.Open(procDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return failed(ReasonProcessGone, false, "%v", err)
	}
	defer unix.Close(pidfd)
	if !sameProcess(pidfd, req.StartTime) {
		return failed(ReasonProcessGone, false, "pid %d is another process now", req.PID)
	}
	if req.Op == OpInspect {
		return inspect(pidfd, req.NSPID)
	}

	nspid := strconv.FormatUint(uint64(req.NSPID), 10)
	sock := filepath.Join(procDir, "root", "tmp", ".java_pid"+nspid)
	signalled := false
	if !isSocket(sock) {
		if !req.AllowSignal {
			return failed(ReasonNoListener, false, "no attach listener, and the JVM may not be signalled")
		}
		// HotSpot starts its attach listener on SIGQUIT only when this
		// trigger file exists and belongs to the JVM's user; otherwise
		// SIGQUIT prints a thread dump.
		trigger, owned, err := createTrigger(procDir, ".attach_pid"+nspid)
		if err != nil {
			return failed(ReasonSignalFailed, false, "create trigger file: %v", err)
		}
		// Only the trigger's creator signals. Another attach (an Insights
		// agent being replaced, or jcmd) owns an existing one: a second
		// SIGQUIT could arrive once the listener runs, and print a thread
		// dump. Wait for its listener instead.
		if owned {
			if err := unix.PidfdSendSignal(pidfd, unix.SIGQUIT, nil, 0); err != nil {
				trigger()
				return failed(ReasonSignalFailed, false, "SIGQUIT: %v", err)
			}
			signalled = true
		}
		err = waitForListener(pidfd, req.StartTime, sock)
		// The listener is up, or will not come: the trigger is done with.
		trigger()
		switch {
		case err == errExited:
			return failed(ReasonProcessGone, signalled, "the JVM exited")
		case err != nil && owned:
			return failed(ReasonListenerTimeout, true, "no attach listener %s after SIGQUIT", listenerTimeout)
		case err != nil:
			return failed(ReasonAttachInProgress, false, "another attach to this JVM started, and its listener did not come up within %s", listenerTimeout)
		}
	}

	props, err := execute(sock, queryTimeout, "properties")
	if err != nil {
		return queryFailure(err, signalled)
	}
	if v := property(props, javatls.MarkerProperty); v != "" {
		return Result{Outcome: AlreadyLoaded, AgentVersion: v, Signalled: signalled}
	}
	if f := property(props, javatls.FailedProperty); f != "" {
		return failed(ReasonEarlierFailure, signalled, "%s", f)
	}
	if req.Op == OpProbe {
		return Result{Outcome: NotLoaded, Signalled: signalled}
	}

	out, err := execute(sock, loadTimeout, "load", "instrument", "false", req.JarPath+"="+req.AgentArgs)
	if err != nil {
		var st *errStatus
		if errors.As(err, &st) {
			return failed(ReasonLoadFailed, signalled, "%v", err)
		}
		return queryFailure(err, signalled)
	}
	if err := loadResult(out); err != nil {
		return failed(ReasonLoadFailed, signalled, "%v", err)
	}

	// The agent records how its start went before agentmain returns.
	props, err = execute(sock, queryTimeout, "properties")
	if err != nil {
		return queryFailure(err, signalled)
	}
	if v := property(props, javatls.MarkerProperty); v != "" {
		return Result{Outcome: Attached, AgentVersion: v, Signalled: signalled}
	}
	if f := property(props, javatls.FailedProperty); f != "" {
		return failed(ReasonAgentFailed, signalled, "%s", f)
	}
	return failed(ReasonProtocol, signalled, "the agent loaded but did not report its state")
}

var (
	errExited  = errors.New("the JVM exited")
	errTimeout = errors.New("timed out")
)

// waitForListener waits until the JVM open as pidfd listens on sock.
func waitForListener(pidfd int, start uint64, sock string) error {
	deadline := time.Now().Add(listenerTimeout)
	for !isSocket(sock) {
		if !sameProcess(pidfd, start) {
			return errExited
		}
		if time.Now().After(deadline) {
			return errTimeout
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

func queryFailure(err error, signalled bool) Result {
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return failed(ReasonConnectFailed, signalled, "%v", err)
	}
	return failed(ReasonProtocol, signalled, "%v", err)
}

// sameProcess reports whether the process open as pidfd started at start.
func sameProcess(pidfd int, start uint64) bool {
	fd, err := unix.Openat(pidfd, "stat", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	f := os.NewFile(uintptr(fd), "stat")
	defer f.Close()
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	got, err := StartTimeFromStat(buf[:n])
	return err == nil && got == start
}

func isSocket(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode()&os.ModeSocket != 0
}

// createTrigger creates name in the JVM's /tmp, resolving the path inside
// the JVM's root. owned reports whether this call created it: when it already
// exists, another attach is starting the listener, unless the file is older
// than staleTriggerAge, which is taken over. The returned func releases the
// trigger, removing it when owned; call it once.
func createTrigger(procDir, name string) (release func(), owned bool, err error) {
	root, err := unix.Open(filepath.Join(procDir, "root"), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, false, err
	}
	defer unix.Close(root)
	tmp, err := openIn(root, "/tmp", unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return nil, false, err
	}
	owned, err = createExclusive(tmp, name)
	if err == nil && !owned && triggerStale(tmp, name) {
		// Left by an attach that was killed. If another attach takes it
		// over first, this one creates nothing and waits.
		_ = unix.Unlinkat(tmp, name, 0)
		owned, err = createExclusive(tmp, name)
	}
	if err != nil {
		unix.Close(tmp)
		return nil, false, err
	}
	return func() {
		if owned {
			_ = unix.Unlinkat(tmp, name, 0)
		}
		unix.Close(tmp)
	}, owned, nil
}

// createExclusive creates name in dir, and reports false if it exists.
func createExclusive(dir int, name string) (bool, error) {
	fd, err := unix.Openat(dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if errors.Is(err, unix.EEXIST) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	unix.Close(fd)
	return true, nil
}

// triggerStale reports whether the trigger name in dir is older than
// staleTriggerAge.
func triggerStale(dir int, name string) bool {
	var st unix.Stat_t
	if err := unix.Fstatat(dir, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false
	}
	return time.Since(time.Unix(st.Mtim.Unix())) > staleTriggerAge
}
