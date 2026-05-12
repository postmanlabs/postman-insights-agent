// Package uprobes handles symbol resolution and uprobe attachment for the
// userspace TLS libraries we target.
//
// For libssl/OpenSSL, the workflow is:
//
//  1. Discover a target process (PID) — done by ebpf/discovery.
//  2. Find the libssl shared object loaded by that process. Two cases:
//       a) Dynamically linked: walk /proc/<pid>/maps for a path matching
//          libssl.so*, return the host-visible path
//          (/proc/<pid>/root/<path>).
//       b) Statically linked: the binary itself contains SSL_* symbols.
//          Open /proc/<pid>/exe and probe it directly.
//  3. Open the binary with link.OpenExecutable and attach uprobes via
//       exe.Uprobe("SSL_read", prog, opts) and exe.Uretprobe("SSL_read", ...)
//     for each of the four symbol pairs (read/read_ex/write/write_ex).
//  4. Keep the returned link.Link handles in an internal map keyed by PID;
//     close them when the PID exits.
//
// On modern Linux (≥4.20), uprobes auto-resolve symbols by name. On older
// kernels we'd need to compute the file offset ourselves via ELF symbol
// table parsing (see ecapture's lib/ for reference).

package uprobes

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// LibSSLPath represents the location of a libssl shared object (or static
// binary that contains SSL_* symbols) discovered for a particular PID.
type LibSSLPath struct {
	// PID this path was discovered for.
	PID uint32

	// HostPath is the path on the agent's filesystem (typically prefixed by
	// /proc/<pid>/root/...) that link.OpenExecutable should open.
	HostPath string

	// Static is true when SSL_* symbols are in the main process binary
	// rather than a separate .so. Used by callers to skip the secondary
	// crypto/etc. probes that wouldn't apply.
	Static bool
}

var libsslPattern = regexp.MustCompile(`/libssl(?:\.so(?:\.\d+)*)?$`)

// FindLibSSL locates the libssl shared object loaded by the given PID by
// reading /proc/<pid>/maps. Returns ErrNotFound if no libssl mapping exists.
//
// This is the "dynamic libssl" case. For statically-linked binaries, callers
// should fall back to FindStaticLibSSL.
func FindLibSSL(pid uint32) (*LibSSLPath, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return nil, fmt.Errorf("uprobes: read %s: %w", mapsPath, err)
	}

	// /proc/<pid>/maps lines look like:
	//   7f... rw-p 00000000 fd:00 ... /usr/lib/x86_64-linux-gnu/libssl.so.3
	for _, line := range strings.Split(string(data), "\n") {
		if !libsslPattern.MatchString(line) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		guestPath := fields[len(fields)-1]
		// Translate to a host-visible path that link.OpenExecutable can open.
		hostPath := filepath.Join(fmt.Sprintf("/proc/%d/root", pid), guestPath)
		if _, statErr := os.Stat(hostPath); statErr != nil {
			// Fallback: use the agent's own filesystem mount of the same
			// path. This works when the agent shares a libssl with the target
			// (uncommon in production, common in dev).
			if _, statErr2 := os.Stat(guestPath); statErr2 == nil {
				hostPath = guestPath
			} else {
				continue
			}
		}
		return &LibSSLPath{PID: pid, HostPath: hostPath, Static: false}, nil
	}

	return nil, ErrNotFound
}

// FindStaticLibSSL handles the case where SSL_* symbols are statically linked
// into the process's main binary (common for Node.js statically built against
// BoringSSL, and for Go binaries that use cgo+OpenSSL).
//
// Implementation deferred to Phase 2 — requires opening /proc/<pid>/exe,
// parsing the ELF symbol table for SSL_read/SSL_write, and confirming they
// resolve to a non-zero offset. See ../../insights-ebpf-research/ecapture/
// for a reference implementation (`lib/openssl/`).
func FindStaticLibSSL(pid uint32) (*LibSSLPath, error) {
	return nil, ErrNotImplemented
}

// ErrNotFound is returned when no libssl mapping is found in a process.
var ErrNotFound = fmt.Errorf("uprobes: libssl not found")

// ErrNotImplemented is a placeholder for Phase-1-deferred functionality.
var ErrNotImplemented = fmt.Errorf("uprobes: not implemented yet")
