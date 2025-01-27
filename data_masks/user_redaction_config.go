package data_masks

import (
	"regexp"
	go_slices "slices"
	"sync"

	"github.com/akitasoftware/akita-libs/api_schema"
	"github.com/akitasoftware/go-utils/sets"
	"github.com/akitasoftware/go-utils/slices"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

type userRedactionConfig struct {
	fieldNames       sets.Set[string]
	fieldNameRegexps []*regexp.Regexp

	// Protects this instance.
	mu sync.RWMutex
}

// Creates a userRedactionConfig instance from the given ServiceAgentConfig.
func newUserRedactionConfig(
	agentConfig *api_schema.ServiceAgentConfig,
) *userRedactionConfig {
	return &userRedactionConfig{
		fieldNames:       sets.NewSet(agentConfig.FieldsToRedact.FieldNames...),
		fieldNameRegexps: agentConfig.FieldsToRedact.FieldNameRegexps,
	}
}

// Determines whether fields with the given name should be redacted according to
// this configuration.
func (c *userRedactionConfig) redactsFieldsNamed(fieldName string) bool {
	if c.fieldNames.Contains(fieldName) {
		return true
	}

	// Determine whether to redact based on user-specified regular expressions.
	for _, re := range c.fieldNameRegexps {
		if re.MatchString(fieldName) {
			return true
		}
	}

	return false
}

// Updates this configuration with the given ServiceAgentConfig.
func (c *userRedactionConfig) update(
	agentConfig *api_schema.ServiceAgentConfig,
) {
	newFieldNames := sets.NewSet(agentConfig.FieldsToRedact.FieldNames...)

	// Filter out empty regular expressions from the incoming configuration. These
	// match everything, which is almost certainly not what is intended. If the
	// user wants to match everything, they can use a different regular
	// expression, such as `$`.
	newFieldNameRegexps := slices.Filter(
		agentConfig.FieldsToRedact.FieldNameRegexps,
		func(re *regexp.Regexp) bool {
			return len(re.String()) > 0
		},
	)

	// Determine whether the two configurations are the same.
	sameConfig := func() bool {
		c.mu.RLock()
		defer c.mu.RUnlock()

		if !newFieldNames.Equals(c.fieldNames) {
			return false
		}

		if !go_slices.EqualFunc(
			c.fieldNameRegexps,
			newFieldNameRegexps,
			func(r1, r2 *regexp.Regexp) bool {
				return r1.String() == r2.String()
			},
		) {
			return false
		}

		return true
	}()

	if sameConfig {
		// Nothing to do.
		return
	}

	// Replace the active configuration with the new one.
	c.mu.Lock()
	defer c.mu.Unlock()
	printer.Debugln("Updating user redaction config")
	printer.Debugf("field names: %v\n", newFieldNames.AsSlice())
	printer.Debugf("field name regexps: %v\n", newFieldNameRegexps)
	c.fieldNames = newFieldNames
	c.fieldNameRegexps = newFieldNameRegexps
}

func (c *userRedactionConfig) RLock() {
	c.mu.RLock()
}

func (c *userRedactionConfig) RUnlock() {
	c.mu.RUnlock()
}
