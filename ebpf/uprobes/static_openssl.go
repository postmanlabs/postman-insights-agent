// SPDX-License-Identifier: Apache-2.0

package uprobes

import (
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// staticLibSSLComms lists /proc/<pid>/comm values for runtimes that commonly
// embed BoringSSL/OpenSSL in the main executable rather than libssl.so.
var staticLibSSLComms = map[string]struct{}{
	"node": {},
}

// requiredStaticSSLSymbols — at least one read and one write entrypoint must
// be present in the executable symbol table before we attach uprobes.
var requiredStaticSSLSymbols = []string{
	"SSL_read",
	"SSL_write",
}

// FindStaticLibSSL is equivalent to FindStaticLibSSLAt("/proc", pid).
func FindStaticLibSSL(pid uint32) (*LibSSLPath, error) {
	return FindStaticLibSSLAt("/proc", pid)
}

// FindStaticLibSSLAt locates SSL_* symbols inside the target's main executable.
// Used for Node.js builds that statically link BoringSSL (official node:20
// images). Returns ErrNotFound when the process is not a candidate or the
// binary does not export the required symbols.
//
// HostPath is /proc/<pid>/root/<exe> when available so link.OpenExecutable
// opens the same inode shown in /proc/<pid>/maps. Symbol checks use the same
// path. Per-PID uprobes are used (validated in dev container for bare Node 20).
func FindStaticLibSSLAt(procRoot string, pid uint32) (*LibSSLPath, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	if !isStaticLibSSLCandidate(procRoot, pid) {
		return nil, ErrNotFound
	}

	attachPath := staticExecutableAttachPath(procRoot, pid)
	if _, err := os.Stat(attachPath); err != nil {
		return nil, fmt.Errorf("uprobes: stat %s: %w", attachPath, err)
	}
	if !hasStaticSSLSymbols(attachPath) {
		return nil, ErrNotFound
	}
	return &LibSSLPath{PID: pid, HostPath: attachPath, Static: true}, nil
}

// staticExecutableAttachPath is passed to link.OpenExecutable. Prefer
// /proc/<pid>/root/<exe> inside containers so the opened inode matches maps.
func staticExecutableAttachPath(procRoot string, pid uint32) string {
	exePath := filepath.Join(procRoot, fmt.Sprintf("%d", pid), "exe")
	target, err := os.Readlink(exePath)
	if err != nil || !strings.HasPrefix(target, "/") {
		return exePath
	}
	rootPath := filepath.Join(procRoot, fmt.Sprintf("%d", pid), "root", target)
	if st, err := os.Stat(rootPath); err == nil && !st.IsDir() {
		return rootPath
	}
	return exePath
}

// staticExecutableELFPath returns the path used for ELF symbol table checks.
func staticExecutableELFPath(procRoot string, pid uint32) string {
	return staticExecutableAttachPath(procRoot, pid)
}

// FindLibSSLAnyAt tries dynamic libssl.so discovery first, then falls back to
// static SSL_* symbols in the main executable (Node BoringSSL).
func FindLibSSLAnyAt(procRoot string, pid uint32) (*LibSSLPath, error) {
	lib, err := FindLibSSLAt(procRoot, pid)
	if err == nil {
		return lib, nil
	}
	if err != ErrNotFound {
		return nil, err
	}
	return FindStaticLibSSLAt(procRoot, pid)
}

func isStaticLibSSLCandidate(procRoot string, pid uint32) bool {
	commPath := filepath.Join(procRoot, fmt.Sprintf("%d", pid), "comm")
	data, err := os.ReadFile(commPath)
	if err == nil {
		comm := strings.TrimSpace(string(data))
		if _, ok := staticLibSSLComms[comm]; ok {
			return true
		}
	}

	exePath := filepath.Join(procRoot, fmt.Sprintf("%d", pid), "exe")
	target, err := os.Readlink(exePath)
	if err != nil {
		return false
	}
	base := filepath.Base(target)
	if _, ok := staticLibSSLComms[base]; ok {
		return true
	}
	return strings.Contains(target, "/node") && !strings.Contains(target, "nodejs")
}

func hasStaticSSLSymbols(exePath string) bool {
	f, err := elf.Open(exePath)
	if err != nil {
		return false
	}
	defer f.Close()

	found := make(map[string]bool, len(requiredStaticSSLSymbols))
	mark := func(syms []elf.Symbol) {
		for _, s := range syms {
			if s.Value == 0 {
				continue
			}
			for _, req := range requiredStaticSSLSymbols {
				if s.Name == req {
					found[req] = true
				}
			}
		}
	}
	if syms, err := f.Symbols(); err == nil {
		mark(syms)
	}
	if syms, err := f.DynamicSymbols(); err == nil {
		mark(syms)
	}
	for _, req := range requiredStaticSSLSymbols {
		if !found[req] {
			return false
		}
	}
	return true
}
