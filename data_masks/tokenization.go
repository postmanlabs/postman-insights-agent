// SPDX-License-Identifier: Apache-2.0
//
// Tokenisation (hash-replace) redaction style.
//
// Two redaction styles from docs/phases/phase-4.md task #5:
//
//   - StyleRedact ("redact"): the default. Replaces matched values with
//     the fixed string RedactionString. Customers see "this field
//     contained something sensitive" but lose all signal.
//
//   - StyleHash ("hash"): replaces matched values with a tokenised form
//     "REDACTED:<16 hex chars>" derived from sha256(value)[:8]. The
//     customer can correlate "is this the same user across two requests?"
//     without ever seeing the raw value. Collision probability for
//     8-byte truncation is ~1 in 4.3 billion per random pair \u2014 acceptable
//     for cardinality estimation but documented in
//     docs/redaction-defaults.md so customers can opt into 16-byte mode
//     if they need it.
//
// The 16-byte ("strong-hash") variant is reserved for a future flag.
// Document the trade-off rather than ship two styles before customers
// ask.

package data_masks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// RedactionStyle is how sensitive values are replaced.
type RedactionStyle string

const (
	StyleRedact RedactionStyle = "redact"
	StyleHash   RedactionStyle = "hash"
)

// ParseRedactionStyle normalises a user-supplied string. Empty defaults to
// StyleRedact (current behaviour).
func ParseRedactionStyle(s string) (RedactionStyle, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "redact":
		return StyleRedact, nil
	case "hash":
		return StyleHash, nil
	default:
		return "", fmt.Errorf("unknown redaction style %q (want one of: redact, hash)", s)
	}
}

// applyRedactionStyle is the single replacement function used by the
// redactor. Centralised so we have one place to change behaviour when we
// add (for example) format-preserving encryption.
func applyRedactionStyle(value string, style RedactionStyle) string {
	switch style {
	case StyleHash:
		sum := sha256.Sum256([]byte(value))
		return "REDACTED:" + hex.EncodeToString(sum[:8])
	default:
		return RedactionString
	}
}
