// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var all = Libraries{OpenSSL: true, Java: true}

func TestParseLibraries(t *testing.T) {
	for _, tc := range []struct {
		names   []string
		want    Libraries
		unknown []string
	}{
		{names: DefaultLibraries, want: Libraries{OpenSSL: true}},
		{names: SupportedLibraries, want: all},
		{names: []string{"openssl"}, want: Libraries{OpenSSL: true}},
		{names: []string{"java"}, want: Libraries{Java: true}},
		{names: []string{" Java ", "OPENSSL"}, want: all},
		{names: []string{"openssl", "gotls"}, want: Libraries{OpenSSL: true}, unknown: []string{"gotls"}},
		{names: []string{"nodejs"}, unknown: []string{"nodejs"}},
		{names: []string{}},
		{names: nil},
	} {
		t.Run(strings.Join(tc.names, ","), func(t *testing.T) {
			got, unknown := ParseLibraries(tc.names)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.unknown, unknown)
		})
	}
}

func TestLibrariesString(t *testing.T) {
	assert.Equal(t, "openssl,java", all.String())
	assert.Equal(t, "java", Libraries{Java: true}.String())
	assert.Equal(t, "none", Libraries{}.String())
	assert.True(t, Libraries{}.None())
	assert.False(t, Libraries{OpenSSL: true}.None())

	// String round-trips through ParseLibraries.
	for _, l := range []Libraries{all, {OpenSSL: true}, {Java: true}} {
		got, unknown := ParseLibraries(strings.Split(l.String(), ","))
		assert.Empty(t, unknown)
		assert.Equal(t, l, got)
	}
}

// With no library to capture, HTTPS capture is off: decided once, at the
// flags.
func TestHTTPSCaptureFromFlags(t *testing.T) {
	for _, tc := range []struct {
		enabled bool
		names   []string
		want    bool
		libs    Libraries
	}{
		{enabled: true, names: DefaultLibraries, want: true, libs: Libraries{OpenSSL: true}},
		{enabled: true, names: []string{"java"}, want: true, libs: Libraries{Java: true}},
		{enabled: true, names: []string{"gotls"}},
		{enabled: true, names: nil},
		{enabled: false, names: SupportedLibraries},
	} {
		on, libs := HTTPSCaptureFromFlags(tc.enabled, tc.names)
		assert.Equal(t, tc.want, on, "%v %v", tc.enabled, tc.names)
		assert.Equal(t, tc.libs, libs, "%v %v", tc.enabled, tc.names)
	}
}

// Java runs for a pod only in a network namespace that is the pod's alone.
func TestLibrariesForPod(t *testing.T) {
	const host = 100
	for _, tc := range []struct {
		podNetns uint64
		want     Libraries
		reason   string
	}{
		{podNetns: 42, want: all},
		{podNetns: 0, want: Libraries{OpenSSL: true}, reason: "the network namespace is unknown"},
		{podNetns: host, want: Libraries{OpenSSL: true}, reason: "the network namespace is the node's (host network)"},
	} {
		assert.Equal(t, tc.want, all.ForPod(tc.podNetns, host), "netns %d", tc.podNetns)
		assert.Equal(t, tc.reason, JavaPodSkipReason(tc.podNetns, host), "netns %d", tc.podNetns)
	}
	assert.True(t, Libraries{Java: true}.ForPod(0, host).None(), "Java only, netns unknown")
}
