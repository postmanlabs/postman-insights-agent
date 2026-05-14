// SPDX-License-Identifier: Apache-2.0
//
// Privacy-mode presets for HTTPS capture.
//
// Three modes from docs/phases/phase-4.md task #3:
//
//   - PrivacyStandard ("standard"): the default. Bodies preserved (subject
//     to size cap), headers redacted by sensitive-key list + regexes,
//     upload to backend enabled.
//
//   - PrivacyStrict ("strict"): bodies dropped entirely. Headers reduced
//     to a small allow-list (content-type, content-length, user-agent).
//     Upload to backend enabled. Suitable for healthcare / financial
//     verticals where the rule is "we can never see customer body bytes
//     leave the host". Method + path + status remain so endpoint shape +
//     latency are still observable.
//
//   - PrivacyDryRun ("dry-run"): capture + redact + sample as usual, but
//     skip the backend upload. The dry-run reporter (see dry_run.go)
//     writes redacted samples to /var/log/postman-insights/dry-run-*.json
//     so the customer's security team can audit what we would have sent
//     before flipping to live mode.
//
// Selection happens at apidump startup based on the --privacy-mode flag.

package data_masks

import (
	"fmt"
	"strings"
)

// PrivacyMode is the agent-wide privacy posture.
type PrivacyMode string

const (
	PrivacyStandard PrivacyMode = "standard"
	PrivacyStrict   PrivacyMode = "strict"
	PrivacyDryRun   PrivacyMode = "dry-run"
)

// PrivacyModeConfig is the resolved configuration for a privacy mode.
// Components read this struct directly; they MUST NOT branch on the
// PrivacyMode string itself, because future modes / customer overrides
// will reuse the config struct with different values.
type PrivacyModeConfig struct {
	Mode PrivacyMode

	// DropBodies: when true, the redactor zeros all request/response body
	// primitives before they leave the host. Method, path, status, and
	// allow-listed headers remain.
	DropBodies bool

	// HeaderAllowlist: when non-empty, headers OUTSIDE this list are
	// zeroed (not redacted-to-string — actually replaced with the type's
	// zero value so downstream type inference still works).
	// Empty slice means "all headers pass through the standard sensitive-
	// key / regex pipeline" (i.e. the existing behaviour).
	//
	// Names are lower-cased on construction so comparison is O(1).
	HeaderAllowlist map[string]struct{}

	// UploadEnabled: when false, the backend collector chain skips upload
	// and the dry-run reporter takes over. Used by PrivacyDryRun.
	UploadEnabled bool
}

// ParsePrivacyMode normalises a user-supplied string into a PrivacyMode.
// Empty string defaults to PrivacyStandard. Unknown values return an error
// so we fail fast at startup instead of silently degrading.
func ParsePrivacyMode(s string) (PrivacyMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "standard":
		return PrivacyStandard, nil
	case "strict":
		return PrivacyStrict, nil
	case "dry-run", "dryrun":
		return PrivacyDryRun, nil
	default:
		return "", fmt.Errorf("unknown privacy mode %q (want one of: standard, strict, dry-run)", s)
	}
}

// Config returns the resolved configuration for this mode.
func (m PrivacyMode) Config() PrivacyModeConfig {
	switch m {
	case PrivacyStrict:
		// Strict: drop bodies, keep a minimal header set.
		// content-type + content-length keep schema/size signal.
		// user-agent helps with workload identification.
		// Do NOT include host or :authority — those can leak tenant-id
		// strings in multi-tenant deployments.
		allow := map[string]struct{}{
			"content-type":   {},
			"content-length": {},
			"user-agent":     {},
		}
		return PrivacyModeConfig{
			Mode:            PrivacyStrict,
			DropBodies:      true,
			HeaderAllowlist: allow,
			UploadEnabled:   true,
		}
	case PrivacyDryRun:
		return PrivacyModeConfig{
			Mode:            PrivacyDryRun,
			DropBodies:      false,
			HeaderAllowlist: nil,
			UploadEnabled:   false,
		}
	default:
		// PrivacyStandard (and any unrecognised mode falls through here
		// as the safe default).
		return PrivacyModeConfig{
			Mode:            PrivacyStandard,
			DropBodies:      false,
			HeaderAllowlist: nil,
			UploadEnabled:   true,
		}
	}
}

// HeaderAllowed returns true if the named header should pass through to
// the backend. Lower-cases the input so callers don't have to.
// An empty allowlist means "all headers allowed".
func (c PrivacyModeConfig) HeaderAllowed(name string) bool {
	if len(c.HeaderAllowlist) == 0 {
		return true
	}
	_, ok := c.HeaderAllowlist[strings.ToLower(name)]
	return ok
}
