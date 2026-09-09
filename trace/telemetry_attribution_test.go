package trace

import "testing"

func TestTelemetryAttributionDirections(t *testing.T) {
	tests := []struct {
		name      string
		isRequest bool
		direction string
	}{
		{name: "request", isRequest: true, direction: "request"},
		{name: "response", isRequest: false, direction: "response"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := messageDirection(tt.isRequest); got != tt.direction {
				t.Fatalf("messageDirection(%v) = %q, want %q", tt.isRequest, got, tt.direction)
			}
		})
	}
}
