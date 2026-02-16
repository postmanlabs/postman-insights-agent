package daemonset

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitServiceName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected [2]string
	}{
		{
			name:     "standard namespace/workload format",
			input:    "default/user-service",
			expected: [2]string{"default", "user-service"},
		},
		{
			name:     "production namespace",
			input:    "production/api-gateway",
			expected: [2]string{"production", "api-gateway"},
		},
		{
			name:     "no namespace separator",
			input:    "just-a-name",
			expected: [2]string{"", "just-a-name"},
		},
		{
			name:     "empty string",
			input:    "",
			expected: [2]string{"", ""},
		},
		{
			name:     "multiple slashes - only split on first",
			input:    "ns/workload/extra",
			expected: [2]string{"ns", "workload/extra"},
		},
		{
			name:     "trailing slash",
			input:    "default/",
			expected: [2]string{"default", ""},
		},
		{
			name:     "leading slash",
			input:    "/workload-name",
			expected: [2]string{"", "workload-name"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitServiceName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
