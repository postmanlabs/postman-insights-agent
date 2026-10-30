package apidump

import "testing"

func TestCheckImplementedModes(t *testing.T) {
	for _, tc := range []struct {
		captureMode, privacy string
		ok                   bool
	}{
		{"truncated", "standard", true},
		{"headers", "standard", false},
		{"full", "standard", false},
		{"", "standard", false},
		{"truncated", "strict", false},
		{"truncated", "dry-run", false},
		{"truncated", "", false},
	} {
		err := checkImplementedModes(tc.captureMode, tc.privacy)
		if (err == nil) != tc.ok {
			t.Errorf("checkImplementedModes(%q, %q) = %v, want ok %v", tc.captureMode, tc.privacy, err, tc.ok)
		}
	}
}
