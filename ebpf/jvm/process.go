// SPDX-License-Identifier: Apache-2.0

// Package jvm finds the Java virtual machines among discovered processes and
// keeps the Java agent's control file fresh in their containers (see
// javatls.ControlFilePath): the agent captures only while that file says so.
package jvm

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/postmanlabs/postman-insights-agent/ebpf/jvm/attach"
)

// Kind is the JVM implementation.
type Kind uint8

const (
	// HotSpot is OpenJDK's JVM (Temurin, Corretto, Zulu, Oracle and so on),
	// which supports dynamic attach.
	HotSpot Kind = iota + 1
	// OpenJ9 (IBM Semeru) attaches differently and is never attached
	// dynamically; the static -javaagent opt-in still works for it.
	OpenJ9
)

func (k Kind) String() string {
	switch k {
	case HotSpot:
		return "hotspot"
	case OpenJ9:
		return "openj9"
	}
	return "unknown"
}

// Process is a JVM found under a /proc mount.
type Process struct {
	// ProcRoot is the /proc mount the JVM was found under: /host/proc in the
	// DaemonSet, /proc otherwise. PID is in that mount's PID namespace.
	ProcRoot string
	PID      uint32
	// StartTime is when the process started, in clock ticks after boot. With
	// PID it identifies the process, so a reused PID is never mistaken for
	// it.
	StartTime uint64
	// NSPID is the PID in the JVM's own PID namespace, which HotSpot's
	// attach files are named after.
	NSPID uint32
	// UID and GID are the effective IDs the JVM runs as.
	UID, GID uint32
	Kind     Kind
	// MountNS is the mount-namespace inode. JVMs that share it share /tmp,
	// and so one control file.
	MountNS uint64
}

// Key identifies a process across PID reuse.
type Key struct {
	PID       uint32
	StartTime uint64
}

// Key returns the process's identity.
func (p *Process) Key() Key { return Key{p.PID, p.StartTime} }

func (p *Process) String() string {
	return fmt.Sprintf("pid=%d (%s, uid %d)", p.PID, p.Kind, p.UID)
}

// ErrNotJVM is returned by Inspect for a process that is not a JVM.
var ErrNotJVM = errors.New("jvm: not a JVM")

// OpenJ9 also ships a libjvm.so (a redirector to libj9vm), so it is checked
// first.
var (
	openJ9LibRE  = regexp.MustCompile(`/libj9vm\d*\.so$`)
	hotSpotLibRE = regexp.MustCompile(`/libjvm\.so$`)
)

// KindFromMaps returns the JVM kind from the content of /proc/<pid>/maps, or
// 0 when no JVM library is mapped. A mapped JVM library is exact, unlike
// guessing from command or image names.
func KindFromMaps(maps []byte) Kind {
	hotSpot := false
	for line := range bytes.SplitSeq(maps, []byte("\n")) {
		line = bytes.TrimRight(line, " ")
		switch {
		case openJ9LibRE.Match(line):
			return OpenJ9
		case hotSpotLibRE.Match(line):
			hotSpot = true
		}
	}
	if hotSpot {
		return HotSpot
	}
	return 0
}

// Inspect returns the JVM running as pid under procRoot, or ErrNotJVM. maps
// is the content of <procRoot>/<pid>/maps when the caller has already read
// it, or nil.
func Inspect(procRoot string, pid uint32, maps []byte) (*Process, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	dir := filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10))
	if maps == nil {
		var err error
		if maps, err = os.ReadFile(filepath.Join(dir, "maps")); err != nil {
			return nil, err
		}
	}
	kind := KindFromMaps(maps)
	if kind == 0 {
		return nil, ErrNotJVM
	}
	p := &Process{ProcRoot: procRoot, PID: pid, Kind: kind}

	var err error
	if p.StartTime, err = StartTime(procRoot, pid); err != nil {
		return nil, err
	}
	status, err := os.ReadFile(filepath.Join(dir, "status"))
	if err != nil {
		return nil, err
	}
	if err := parseStatus(status, p); err != nil {
		return nil, fmt.Errorf("jvm: %s/status: %w", dir, err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Join(dir, "ns", "mnt"), &st); err != nil {
		return nil, err
	}
	p.MountNS = st.Ino
	return p, nil
}

// parseStatus fills NSPID, UID and GID from /proc/<pid>/status.
func parseStatus(status []byte, p *Process) error {
	var haveNSPID, haveUID, haveGID bool
	for line := range strings.SplitSeq(string(status), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		switch key {
		case "NSpid":
			// The PID in each nested PID namespace, outermost first; the
			// last is the process's own namespace.
			n, err := strconv.ParseUint(fields[len(fields)-1], 10, 32)
			if err != nil {
				return fmt.Errorf("NSpid: %w", err)
			}
			p.NSPID, haveNSPID = uint32(n), true
		case "Uid", "Gid":
			// Real, effective, saved and filesystem IDs.
			if len(fields) < 2 {
				return fmt.Errorf("%s: %q", key, value)
			}
			n, err := strconv.ParseUint(fields[1], 10, 32)
			if err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
			if key == "Uid" {
				p.UID, haveUID = uint32(n), true
			} else {
				p.GID, haveGID = uint32(n), true
			}
		}
	}
	if !haveNSPID || !haveUID || !haveGID {
		return errors.New("missing NSpid, Uid or Gid")
	}
	return nil
}

// StartTime returns when pid started, in clock ticks after boot (field 22 of
// /proc/<pid>/stat).
func StartTime(procRoot string, pid uint32) (uint64, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	path := filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10), "stat")
	stat, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return parseStartTime(stat)
}

func parseStartTime(stat []byte) (uint64, error) {
	return attach.StartTimeFromStat(stat)
}

// Alive reports whether p is still running: its PID exists and has the same
// start time.
func Alive(p *Process) bool {
	t, err := StartTime(p.ProcRoot, p.PID)
	return err == nil && t == p.StartTime
}
