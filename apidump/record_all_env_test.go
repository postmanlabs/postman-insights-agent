package apidump

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The environments record-all may run in are an allowlist, not a denylist: an
// environment nobody thought about must not be able to upload successful
// response bodies. Pinned here so widening it is a deliberate edit to a test.
func TestRecordAllAllowedIn(t *testing.T) {
	for _, env := range []string{"DEV", "BETA"} {
		assert.True(t, recordAllAllowedIn(env), "%s should allow record-all", env)
	}

	for _, env := range []string{
		"PRODUCTION",
		"PREVIEW",
		"STAGE",
		// An unset POSTMAN_ENV reaches here as PRODUCTION (see
		// postmanEnvironment), but guard the empty string too in case a caller
		// ever passes the raw value.
		"",
		// postmanEnvironment upper-cases, so a lower-case value means someone
		// bypassed it; fail closed rather than match loosely.
		"beta",
		"dev",
	} {
		assert.False(t, recordAllAllowedIn(env), "%q should not allow record-all", env)
	}
}
