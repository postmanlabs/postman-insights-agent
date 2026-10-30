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
		{names: DefaultLibraries, want: all},
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
		{enabled: true, names: DefaultLibraries, want: true, libs: all},
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
func TestPodNetnsSkipReason(t *testing.T) {
	const host = 100
	for _, tc := range []struct {
		podNetns, hostNetns uint64
		reason              string
	}{
		{podNetns: 42, hostNetns: host},
		{podNetns: 0, hostNetns: host, reason: "its network namespace is unknown"},
		{podNetns: host, hostNetns: host, reason: "it is on the node's network (hostNetwork)"},
		{podNetns: 42, hostNetns: 0, reason: "the node's network namespace is unknown"},
	} {
		assert.Equal(t, tc.reason, PodNetnsSkipReason(tc.podNetns, tc.hostNetns), "pod netns %d, node netns %d", tc.podNetns, tc.hostNetns)
	}
}

func TestStandaloneScope(t *testing.T) {
	for _, tc := range []struct {
		name         string
		inKubernetes bool
		ownNetns     uint64
		hostNetwork  bool
		want         uint64
		reason       string
	}{
		{name: "host", ownNetns: 42, want: 0},
		{name: "host, own netns unknown", ownNetns: 0, want: 0},
		{name: "pod", inKubernetes: true, ownNetns: 42, want: 42},
		{name: "pod, own netns unknown", inKubernetes: true, ownNetns: 0, reason: "its network namespace is unknown"},
		{name: "pod on the host network", inKubernetes: true, ownNetns: 42, hostNetwork: true, reason: "it is on the node's network (hostNetwork)"},
	} {
		netns, reason := StandaloneScope(tc.inKubernetes, tc.ownNetns, tc.hostNetwork)
		assert.Equal(t, tc.want, netns, tc.name)
		assert.Equal(t, tc.reason, reason, tc.name)
	}
}
