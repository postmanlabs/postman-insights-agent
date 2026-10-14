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

// DefaultLibraries is the default of --https-libraries. Java capture is in
// preview, so it is off until --https-libraries names it; it joins the
// default at the preview release.
var DefaultLibraries = []string{LibraryOpenSSL}

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
