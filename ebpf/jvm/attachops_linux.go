// SPDX-License-Identifier: Apache-2.0

//go:build linux

package jvm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// maxPerfDataSize bounds how much of a perf data file is read (HotSpot's
// default is 32 KiB).
const maxPerfDataSize = 1 << 20

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

func (o linuxOps) inspect(p *Process) (gateInfo, error) {
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

	if args, err := perfDataArgs(p); err == nil {
		info.args, info.argsSource = strings.Fields(args), "hsperfdata"
		return info, nil
	}
	cmdline, err := os.ReadFile(filepath.Join(dir, "cmdline"))
	if err != nil {
		return info, err
	}
	environ, err := os.ReadFile(filepath.Join(dir, "environ"))
	if err != nil {
		return info, err
	}
	info.args, info.argsSource = argsFromCmdline(cmdline, environ), "command line and environment"
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

// perfDataArgs returns the JVM's effective arguments from its perf data file
// /tmp/hsperfdata_<user>/<nspid>, which must belong to the JVM's user.
func perfDataArgs(p *Process) (string, error) {
	root, err := openRoot(p)
	if err != nil {
		return "", err
	}
	defer unix.Close(root)
	return perfDataArgsIn(root, p.NSPID, p.UID)
}

// perfDataArgsIn is perfDataArgs in the container whose root is open as root.
func perfDataArgsIn(root int, nspidNum, uid uint32) (string, error) {
	tmp, err := openIn(root, "/tmp", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return "", err
	}
	tmpDir := os.NewFile(uintptr(tmp), "/tmp")
	names, err := tmpDir.Readdirnames(-1)
	tmpDir.Close()
	if err != nil {
		return "", err
	}
	nspid := strconv.FormatUint(uint64(nspidNum), 10)
	for _, name := range names {
		if !strings.HasPrefix(name, "hsperfdata_") {
			continue
		}
		data, err := readOwnedFile(root, path.Join("/tmp", name, nspid), uid)
		if err != nil {
			continue
		}
		entries, err := parsePerfData(data)
		if err != nil {
			continue
		}
		if args, ok := entries["java.rt.vmArgs"]; ok {
			return args + " " + entries["java.rt.vmFlags"], nil
		}
	}
	return "", errors.New("no perf data")
}

// readOwnedFile reads a regular file inside the container that belongs to
// uid.
func readOwnedFile(root int, name string, uid uint32) ([]byte, error) {
	fd, err := openIn(root, name, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uid {
		return nil, fmt.Errorf("%s: not a file of uid %d", name, uid)
	}
	return io.ReadAll(io.LimitReader(f, maxPerfDataSize))
}

// agentJarName is the jar's name in the container.
const agentJarName = "postman-java-agent.jar"

func (o linuxOps) stage(p *Process, jar []byte, dirName string) (string, error) {
	root, err := openRoot(p)
	if err != nil {
		return "", err
	}
	defer unix.Close(root)
	return stageIn(root, jar, dirName)
}

// stageIn copies jar to /tmp/.postman-insights/<dirName>/ in the container
// whose root is open as root, and returns its path there.
func stageIn(root int, jar []byte, dirName string) (string, error) {
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
	return path.Join(agentDirParent, agentDirName, dirName, agentJarName), nil
}

// helperTimeout bounds one run of the helper, which bounds each of its steps
// itself.
const helperTimeout = 2 * time.Minute

func (o linuxOps) attach(ctx context.Context, p *Process, req attach.Request) (attach.Result, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return attach.Result{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, helperTimeout)
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
