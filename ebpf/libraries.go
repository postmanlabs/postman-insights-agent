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

// Why a pod's HTTPS capture cannot be confined to the pod.
const (
	skipPodNetnsUnknown  = "its network namespace is unknown"
	skipNodeNetnsUnknown = "the node's network namespace is unknown"
	skipHostNetwork      = "it is on the node's network (hostNetwork)"
)

// PodNetnsSkipReason returns why HTTPS capture cannot be confined to a pod in
// network namespace podNetns on a node whose own namespace is hostNetns, or
// "" when it can. OpenSSL processes are probed, Java frames accepted and JVMs
// controlled per network namespace, so the namespace must be the pod's alone:
// known, and not the node's, which hostNetwork pods and host processes
// share; and the node's must be known, or the pod's could be it. Capturing
// anyway would take in other pods' and the node's traffic as this pod's.
func PodNetnsSkipReason(podNetns, hostNetns uint64) string {
	switch {
	case podNetns == 0:
		return skipPodNetnsUnknown
	case hostNetns == 0:
		return skipNodeNetnsUnknown
	case podNetns == hostNetns:
		return skipHostNetwork
	}
	return ""
}

// StandaloneScope returns the network namespace a standalone agent (apidump
// outside the DaemonSet) confines HTTPS capture to when it is given no other
// scope, or why it captures nothing; 0 and "" mean it is not confined.
//
// In a Kubernetes pod (a sidecar) the agent captures only in its own network
// namespace, ownNetns, which all the pod's containers share: with hostPID,
// which a sidecar needs for HTTPS capture, it sees every process on the node,
// and would otherwise capture other pods' traffic as its own. A pod on the
// node's network (hostNetwork) shares its namespace with host processes and
// other hostNetwork pods, and an unknown one identifies nothing, so then it
// captures nothing, as a DaemonSet does for such pods (PodNetnsSkipReason).
// An agent on a host, outside Kubernetes, captures the host's processes.
func StandaloneScope(inKubernetes bool, ownNetns uint64, hostNetwork bool) (netns uint64, skipReason string) {
	switch {
	case !inKubernetes:
		return 0, ""
	case ownNetns == 0:
		return 0, skipPodNetnsUnknown
	case hostNetwork:
		return 0, skipHostNetwork
	}
	return ownNetns, ""
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
