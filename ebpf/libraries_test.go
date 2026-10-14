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
