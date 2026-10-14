// SPDX-License-Identifier: Apache-2.0

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

// Run performs req and reports the outcome. It must run as the JVM's user.
func Run(req Request) Result {
	if req.Version != RequestVersion1 || req.PID == 0 || req.NSPID == 0 || req.JarPath == "" {
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
		trigger, err := createTrigger(procDir, ".attach_pid"+nspid)
		if err != nil {
			return failed(ReasonSignalFailed, false, "create trigger file: %v", err)
		}
		defer trigger()
		if err := unix.PidfdSendSignal(pidfd, unix.SIGQUIT, nil, 0); err != nil {
			return failed(ReasonSignalFailed, false, "SIGQUIT: %v", err)
		}
		signalled = true
		deadline := time.Now().Add(listenerTimeout)
		for !isSocket(sock) {
			if !sameProcess(pidfd, req.StartTime) {
				return failed(ReasonProcessGone, true, "the JVM exited")
			}
			if time.Now().After(deadline) {
				return failed(ReasonListenerTimeout, true, "no attach listener %s after SIGQUIT", listenerTimeout)
			}
			time.Sleep(50 * time.Millisecond)
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
// the JVM's root, and returns a func that removes it.
func createTrigger(procDir, name string) (func(), error) {
	root, err := unix.Open(filepath.Join(procDir, "root"), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(root)
	tmp, err := unix.Openat2(root, "/tmp", &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(tmp, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		unix.Close(tmp)
		return nil, err
	}
	created := err == nil
	if created {
		unix.Close(fd)
	}
	return func() {
		if created {
			_ = unix.Unlinkat(tmp, name, 0)
		}
		unix.Close(tmp)
	}, nil
}
