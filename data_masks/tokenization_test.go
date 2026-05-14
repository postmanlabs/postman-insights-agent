// SPDX-License-Identifier: Apache-2.0

package data_masks

import (
	"strings"
	"testing"
)

func TestParseRedactionStyle(t *testing.T) {
	cases := []struct {
		in      string
		want    RedactionStyle
		wantErr bool
	}{
		{"", StyleRedact, false},
		{"redact", StyleRedact, false},
		{"REDACT", StyleRedact, false},
		{"hash", StyleHash, false},
		{" hash ", StyleHash, false},
		{"sha256", "", true},
	}
	for _, c := range cases {
		got, err := ParseRedactionStyle(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseRedactionStyle(%q): want error", c.in)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("ParseRedactionStyle(%q) = %v, %v; want %v", c.in, got, err, c.want)
		}
	}
}

func TestApplyRedactionStyle(t *testing.T) {
	// StyleRedact: fixed string regardless of input.
	if applyRedactionStyle("foo", StyleRedact) != RedactionString {
		t.Errorf("StyleRedact must replace with %q", RedactionString)
	}

	// StyleHash: deterministic for equal inputs.
	a := applyRedactionStyle("user-12345", StyleHash)
	b := applyRedactionStyle("user-12345", StyleHash)
	if a != b {
		t.Errorf("hash must be deterministic; got %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "REDACTED:") {
		t.Errorf("hash output must be prefixed REDACTED:, got %q", a)
	}
	if len(a) != len("REDACTED:")+16 {
		t.Errorf("hash output must be 16 hex chars (8 bytes), got %d", len(a)-len("REDACTED:"))
	}

	// StyleHash: different inputs produce different outputs.
	c := applyRedactionStyle("user-67890", StyleHash)
	if a == c {
		t.Errorf("hash must differ for different inputs")
	}
}
