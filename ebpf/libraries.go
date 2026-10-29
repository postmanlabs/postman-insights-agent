// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"strings"

	"github.com/postmanlabs/postman-insights-agent/printer"
)

// The TLS libraries HTTPS capture can probe, as --https-libraries names them.
const (
	// LibraryOpenSSL is libssl, probed with uprobes.
	LibraryOpenSSL = "openssl"
	// LibraryJava is Java's TLS (JSSE and Netty engines), captured by the
	// Java agent.
	LibraryJava = "java"
)

// SupportedLibraries are the names --https-libraries takes.
var SupportedLibraries = []string{LibraryOpenSSL, LibraryJava}

// DefaultLibraries is the default of --https-libraries: every supported
// library, so --enable-https-capture alone covers Java too (in preview).
// --https-libraries=openssl turns Java capture off.
var DefaultLibraries = []string{LibraryOpenSSL, LibraryJava}

// Libraries is the set of TLS libraries HTTPS capture probes.
type Libraries struct {
	OpenSSL bool
	Java    bool
}

// ParseLibraries parses the names given to --https-libraries, ignoring case
// and surrounding space. It returns the names it does not know apart from the
// set.
func ParseLibraries(names []string) (libs Libraries, unknown []string) {
	for _, name := range names {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case LibraryOpenSSL:
			libs.OpenSSL = true
		case LibraryJava:
			libs.Java = true
		default:
			unknown = append(unknown, name)
		}
	}
	return libs, unknown
}

// LibrariesFromFlag is ParseLibraries for the --https-libraries flag. It warns
// about the names it does not know and ignores them, rather than failing: an
// agent that refused to start would stop all capture, not only HTTPS.
func LibrariesFromFlag(names []string) Libraries {
	libs, unknown := ParseLibraries(names)
	if len(unknown) > 0 {
		printer.Stderr.Warningf("--https-libraries: ignoring %s (supported: %s)\n",
			strings.Join(unknown, ", "), strings.Join(SupportedLibraries, ", "))
	}
	if libs.None() {
		printer.Stderr.Warningf("--https-libraries names no supported library, so HTTPS capture is off\n")
	}
	return libs
}

// HTTPSCaptureFromFlags returns whether HTTPS capture runs, and from which
// libraries, for --enable-https-capture and --https-libraries: off when the
// libraries name none it supports, so that nothing downstream sees HTTPS
// capture on with nothing to capture.
func HTTPSCaptureFromFlags(enabled bool, names []string) (bool, Libraries) {
	if !enabled {
		return false, Libraries{}
	}
	libs := LibrariesFromFlag(names)
	if libs.None() {
		return false, Libraries{}
	}
	return true, libs
}

// JavaPodSkipReason returns why Java capture cannot run for a pod in network
// namespace podNetns on a node whose own namespace is hostNetns, or "" when it
// can. Java frames are accepted, and JVMs controlled, per network namespace,
// so the namespace must be the pod's alone: known, and not the host's, which
// hostNetwork pods and host processes share. Accepting more would capture
// and control other pods' JVMs as this pod's.
func JavaPodSkipReason(podNetns, hostNetns uint64) string {
	switch {
	case podNetns == 0:
		return "the network namespace is unknown"
	case podNetns == hostNetns:
		return "the network namespace is the node's (host network)"
	}
	return ""
}

// ForPod returns the libraries a pod is captured from when the node captures
// from l: without Java when JavaPodSkipReason gives a reason.
func (l Libraries) ForPod(podNetns, hostNetns uint64) Libraries {
	if JavaPodSkipReason(podNetns, hostNetns) != "" {
		l.Java = false
	}
	return l
}

// None reports whether the set is empty.
func (l Libraries) None() bool { return !l.OpenSSL && !l.Java }

// String lists the libraries as --https-libraries takes them, or "none".
func (l Libraries) String() string {
	var names []string
	if l.OpenSSL {
		names = append(names, LibraryOpenSSL)
	}
	if l.Java {
		names = append(names, LibraryJava)
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ",")
}
