package trace

import "testing"

func TestTelemetryAttributionDirections(t *testing.T) {
	tests := []struct {
		name        string
		isRequest   bool
		direction   string
		missingHalf string
	}{
		{name: "request", isRequest: true, direction: "request", missingHalf: "response"},
		{name: "response", isRequest: false, direction: "response", missingHalf: "request"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := messageDirection(tt.isRequest); got != tt.direction {
				t.Fatalf("messageDirection(%v) = %q, want %q", tt.isRequest, got, tt.direction)
			}
			if got := missingHalf(tt.isRequest); got != tt.missingHalf {
				t.Fatalf("missingHalf(%v) = %q, want %q", tt.isRequest, got, tt.missingHalf)
			}
		})
	}
}
