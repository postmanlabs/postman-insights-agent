//go:build linux

package jvm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/postmanlabs/postman-insights-agent/ebpf/jvm/attach"
)

// clockTicksPerSecond is USER_HZ, the unit of /proc/<pid>/stat times; 100 on
// every Linux architecture the agent supports.
const clockTicksPerSecond = 100

// linuxOps is attachOps for real JVMs.
type linuxOps struct {
	helperPath string
}

func platformOps(helperPath string) (attachOps, error) {
	return linuxOps{helperPath: helperPath}, nil
}

func (o linuxOps) alive(p *Process) bool { return Alive(p) }

// inspectTimeout bounds one inspect run of the helper.
const inspectTimeout = 30 * time.Second

func (o linuxOps) inspect(ctx context.Context, p *Process) (gateInfo, error) {
	var info gateInfo
	dir := filepath.Join(p.ProcRoot, strconv.FormatUint(uint64(p.PID), 10))

	uptime, err := os.ReadFile(filepath.Join(p.ProcRoot, "uptime"))
	if err != nil {
		return info, err
	}
	up, err := strconv.ParseFloat(strings.Fields(string(uptime) + " 0")[0], 64)
	if err != nil {
		return info, fmt.Errorf("uptime: %w", err)
	}
	info.age = time.Duration((up - float64(p.StartTime)/clockTicksPerSecond) * float64(time.Second))

	status, err := os.ReadFile(filepath.Join(dir, "status"))
	if err != nil {
		return info, err
	}
	info.sigQuitCaught = sigQuitCaught(status)

	// The JVM's perf data and environment are readable only by its user.
	// The helper reads them as that user: reading them here, as root,
	// would take a capability that bypasses every file permission on the
	// node (DAC_OVERRIDE or DAC_READ_SEARCH).
	res, err := o.runHelper(ctx, p, attach.Request{
		Version:   attach.RequestVersion1,
		Op:        attach.OpInspect,
		ProcRoot:  p.ProcRoot,
		PID:       p.PID,
		StartTime: p.StartTime,
		NSPID:     p.NSPID,
	}, inspectTimeout)
	if err != nil {
		return info, err
	}
	switch {
	case res.Outcome == attach.Inspected && res.Inspection != nil:
	case res.Reason == attach.ReasonInspectFailed:
		return info, errors.New(res.Detail)
	default:
		return info, fmt.Errorf("%s: %s", res.Reason, res.Detail)
	}
	if entries := res.Inspection.PerfData; entries != nil {
		// HotSpot joins the arguments with spaces, so one containing spaces
		// splits; whether attach is on comes from the JVM itself instead.
		info.args = strings.Fields(entries["java.rt.vmArgs"] + " " + entries["java.rt.vmFlags"])
		info.attachOn, info.attachKnown = perfDataAttach(entries)
		info.argsSource = "hsperfdata"
		return info, nil
	}
	cmdline, err := os.ReadFile(filepath.Join(dir, "cmdline"))
	if err != nil {
		return info, err
	}
	info.args, info.argsSource = argsFromCmdline(cmdline, res.Inspection.JavaOptions), "command line and environment"
	return info, nil
}

// sigQuitCaught reports whether /proc/<pid>/status shows a SIGQUIT handler.
// HotSpot installs one unless started with -Xrs; without it, SIGQUIT would
// kill the JVM.
func sigQuitCaught(status []byte) bool {
	for line := range strings.SplitSeq(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "SigCgt:"); ok {
			mask, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			return err == nil && mask&(1<<(uint(syscall.SIGQUIT)-1)) != 0
		}
	}
	return false
}

// agentJarName is the jar's name in the container.
const agentJarName = "postman-insights-java-agent.jar"

func (o linuxOps) stage(p *Process, jar []byte, dirName string, now time.Time) (string, error) {
	root, err := openRoot(p)
	if err != nil {
		return "", err
	}
	defer unix.Close(root)
	return stageWithRetry(root, jar, dirName, now)
}

// stageWithRetry is stageIn, run once more when a file or directory it was
// using is removed under it (ENOENT): another Insights agent's cleanup may
// remove an old copy just as this agent reuses it. The second run creates
// the copy anew, and no cleanup removes a copy that young.
func stageWithRetry(root int, jar []byte, dirName string, now time.Time) (string, error) {
	p, err := stageIn(root, jar, dirName, now)
	if errors.Is(err, unix.ENOENT) {
		p, err = stageIn(root, jar, dirName, now)
	}
	return p, err
}

// afterCopyCheck, when set, runs in stageIn between its check of an existing
// copy and its use; tests remove the copy there.
var afterCopyCheck func()

// stageIn copies jar to /tmp/.postman-insights/<dirName>/ in the container
// whose root is open as root, and returns its path there. It sets the jar's
// modification time to now, also when the copy is there already, so other
// Insights agents leave the copy alone while it is about to be loaded (see
// removeStaleCopiesIn).
func stageIn(root int, jar []byte, dirName string, now time.Time) (string, error) {
	agentDir, err := openAgentDir(root, true)
	if err != nil {
		return "", err
	}
	defer unix.Close(agentDir)
	dir, err := openOwnedDir(agentDir, dirName, true)
	if err != nil {
		return "", fmt.Errorf("%s: %w", dirName, err)
	}
	defer unix.Close(dir)

	// The directory is named after the jar's checksum and only this agent
	// can write to it, so a complete copy is the right jar.
	var st unix.Stat_t
	if err := unix.Fstatat(dir, agentJarName, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || st.Size != int64(len(jar)) {
		if err := writeFileAtomic(dir, agentJarName, jar); err != nil {
			return "", err
		}
	}
	if afterCopyCheck != nil {
		afterCopyCheck()
	}
	ts := unix.NsecToTimespec(now.UnixNano())
	if err := unix.UtimesNanoAt(dir, agentJarName, []unix.Timespec{ts, ts}, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return "", fmt.Errorf("set the modification time of %s: %w", agentJarName, err)
	}
	return path.Join(agentDirParent, agentDirName, dirName, agentJarName), nil
}

// attachTimeout bounds one attach run of the helper, which bounds each of its
// steps itself.
const attachTimeout = 2 * time.Minute

func (o linuxOps) attach(ctx context.Context, p *Process, req attach.Request) (attach.Result, error) {
	return o.runHelper(ctx, p, req, attachTimeout)
}

// runHelper runs the helper as p's user to perform req.
func (o linuxOps) runHelper(ctx context.Context, p *Process, req attach.Request, timeout time.Duration) (attach.Result, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return attach.Result{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, o.helperPath)
	// The helper runs as the JVM's user, with no supplementary groups and
	// so no capabilities, and dies with this process.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: p.UID, Gid: p.GID, Groups: []uint32{}},
		Pdeathsig:  syscall.SIGKILL,
	}
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.Stdin = bytes.NewReader(body)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()

	var res attach.Result
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		if runErr == nil {
			runErr = err
		}
		return attach.Result{}, fmt.Errorf("%s: %v (%s)", o.helperPath, runErr, strings.TrimSpace(stderr.String()))
	}
	return res, nil
}
