package apidump

import (
	"testing"

	"github.com/akitasoftware/akita-libs/client_telemetry"
)

func TestMergePacketCountSummariesIncludesHTTPSCounts(t *testing.T) {
	httpSummary := &client_telemetry.PacketCountSummary{
		Version: client_telemetry.Version,
		Total: client_telemetry.PacketCounts{
			HTTPRequests:  2,
			HTTPResponses: 3,
		},
		ObservationWindow: client_telemetry.PacketCounts{
			HTTPRequests:  1,
			HTTPResponses: 1,
		},
		TopByPort: map[int]*client_telemetry.PacketCounts{
			443: &client_telemetry.PacketCounts{
				SrcPort:      443,
				HTTPRequests: 1,
			},
		},
		TopByInterface: map[string]*client_telemetry.PacketCounts{
			"en0": &client_telemetry.PacketCounts{
				Interface:    "en0",
				HTTPRequests: 2,
			},
		},
		TopByHost: map[string]*client_telemetry.PacketCounts{
			"example.com": &client_telemetry.PacketCounts{
				SrcHost:      "example.com",
				HTTPRequests: 2,
			},
		},
		ByPortOverflow: &client_telemetry.PacketCounts{
			HTTPRequests: 1,
		},
	}

	httpsSummary := &client_telemetry.PacketCountSummary{
		Version: client_telemetry.Version,
		Total: client_telemetry.PacketCounts{
			HTTPSRequests:  5,
			HTTPSResponses: 7,
		},
		ObservationWindow: client_telemetry.PacketCounts{
			HTTPSRequests:  2,
			HTTPSResponses: 3,
		},
		TopByPort: map[int]*client_telemetry.PacketCounts{
			443: &client_telemetry.PacketCounts{
				SrcPort:        443,
				HTTPSRequests:  4,
				HTTPSResponses: 6,
			},
		},
		TopByInterface: map[string]*client_telemetry.PacketCounts{
			"en0": &client_telemetry.PacketCounts{
				Interface:      "en0",
				HTTPSRequests:  5,
				HTTPSResponses: 7,
			},
		},
		TopByHost: map[string]*client_telemetry.PacketCounts{
			"example.com": &client_telemetry.PacketCounts{
				SrcHost:        "example.com",
				HTTPSRequests:  5,
				HTTPSResponses: 7,
			},
		},
		ByPortOverflow: &client_telemetry.PacketCounts{
			HTTPSRequests: 2,
		},
	}

	merged := mergePacketCountSummaries(httpSummary, httpsSummary)

	if merged.Total.HTTPRequests != 2 || merged.Total.HTTPResponses != 3 {
		t.Fatalf("expected HTTP totals to be preserved, got %+v", merged.Total)
	}
	if merged.Total.HTTPSRequests != 5 || merged.Total.HTTPSResponses != 7 {
		t.Fatalf("expected HTTPS totals to be merged, got %+v", merged.Total)
	}
	if merged.ObservationWindow.HTTPSRequests != 2 || merged.ObservationWindow.HTTPSResponses != 3 {
		t.Fatalf("expected HTTPS window counts to be merged, got %+v", merged.ObservationWindow)
	}
	if merged.TopByPort[443].HTTPRequests != 1 || merged.TopByPort[443].HTTPSRequests != 4 {
		t.Fatalf("expected merged port breakdown, got %+v", merged.TopByPort[443])
	}
	if merged.ByPortOverflow.HTTPRequests != 1 || merged.ByPortOverflow.HTTPSRequests != 2 {
		t.Fatalf("expected merged overflow counts, got %+v", merged.ByPortOverflow)
	}

	if httpSummary.Total.HTTPSRequests != 0 || httpSummary.TopByPort[443].HTTPSRequests != 0 {
		t.Fatalf("expected source summary to remain unchanged, got %+v", httpSummary)
	}
}
