// SPDX-License-Identifier: Apache-2.0

package data_masks

import "testing"

func TestParsePrivacyMode(t *testing.T) {
	cases := []struct {
		in      string
		want    PrivacyMode
		wantErr bool
	}{
		{"", PrivacyStandard, false},
		{"standard", PrivacyStandard, false},
		{"STANDARD", PrivacyStandard, false},
		{"strict", PrivacyStrict, false},
		{"Strict", PrivacyStrict, false},
		{"dry-run", PrivacyDryRun, false},
		{"dryrun", PrivacyDryRun, false},
		{" dry-run ", PrivacyDryRun, false},
		{"nonsense", "", true},
	}
	for _, c := range cases {
		got, err := ParsePrivacyMode(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParsePrivacyMode(%q): want error, got %v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePrivacyMode(%q): unexpected error: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("ParsePrivacyMode(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestPrivacyModeConfig(t *testing.T) {
	std := PrivacyStandard.Config()
	if std.DropBodies || !std.UploadEnabled || len(std.HeaderAllowlist) != 0 {
		t.Errorf("standard config wrong: %+v", std)
	}

	strict := PrivacyStrict.Config()
	if !strict.DropBodies {
		t.Error("strict must drop bodies")
	}
	if !strict.UploadEnabled {
		t.Error("strict must still upload")
	}
	if !strict.HeaderAllowed("Content-Type") {
		t.Error("strict allowlist must include content-type (case-insensitive)")
	}
	if strict.HeaderAllowed("Authorization") {
		t.Error("strict allowlist must reject authorization")
	}
	if strict.HeaderAllowed("Host") {
		t.Error("strict allowlist intentionally excludes host (tenant leak)")
	}

	dry := PrivacyDryRun.Config()
	if dry.UploadEnabled {
		t.Error("dry-run must NOT upload")
	}
	if dry.DropBodies {
		t.Error("dry-run must NOT drop bodies (point is to inspect what would have been sent)")
	}
}

func TestHeaderAllowed_EmptyMeansAll(t *testing.T) {
	c := PrivacyStandard.Config()
	if !c.HeaderAllowed("anything") {
		t.Error("empty allowlist must accept any header")
	}
}
