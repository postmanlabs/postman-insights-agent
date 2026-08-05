package apidump

import (
	"github.com/akitasoftware/akita-libs/client_telemetry"
	"github.com/postmanlabs/postman-insights-agent/trace"
)

func summaryOrNil(counter *trace.PacketCounter, n int) *client_telemetry.PacketCountSummary {
	if counter == nil {
		return nil
	}
	return counter.Summary(n)
}

func mergePacketCountSummaries(dst, src *client_telemetry.PacketCountSummary) *client_telemetry.PacketCountSummary {
	if dst == nil {
		return copyPacketCountSummary(src)
	}

	merged := copyPacketCountSummary(dst)
	if src == nil {
		return merged
	}

	mergePacketCounts(&merged.Total, &src.Total)
	mergePacketCounts(&merged.ObservationWindow, &src.ObservationWindow)
	merged.TopByPort = mergePacketCountMap(merged.TopByPort, src.TopByPort)
	merged.TopByInterface = mergePacketCountMap(merged.TopByInterface, src.TopByInterface)
	merged.TopByHost = mergePacketCountMap(merged.TopByHost, src.TopByHost)
	mergePacketCountOverflow(&merged.ByPortOverflow, src.ByPortOverflow)
	mergePacketCountOverflow(&merged.ByInterfaceOverflow, src.ByInterfaceOverflow)
	mergePacketCountOverflow(&merged.ByHostOverflow, src.ByHostOverflow)
	if merged.ByPortOverflowLimit == 0 {
		merged.ByPortOverflowLimit = src.ByPortOverflowLimit
	}
	if merged.ByInterfaceOverflowLimit == 0 {
		merged.ByInterfaceOverflowLimit = src.ByInterfaceOverflowLimit
	}
	if merged.ByHostOverflowLimit == 0 {
		merged.ByHostOverflowLimit = src.ByHostOverflowLimit
	}
	if merged.Version == "" {
		merged.Version = src.Version
	}

	return merged
}

func mergePacketCounts(dst, src *client_telemetry.PacketCounts) {
	if dst == nil || src == nil {
		return
	}
	dst.Add(*src)
}

func copyPacketCountSummary(summary *client_telemetry.PacketCountSummary) *client_telemetry.PacketCountSummary {
	if summary == nil {
		return nil
	}

	return &client_telemetry.PacketCountSummary{
		Version:                  summary.Version,
		Total:                    *summary.Total.Copy(),
		ObservationWindow:        *summary.ObservationWindow.Copy(),
		TopByPort:                copyPacketCountMap(summary.TopByPort),
		TopByInterface:           copyPacketCountMap(summary.TopByInterface),
		TopByHost:                copyPacketCountMap(summary.TopByHost),
		ByPortOverflowLimit:      summary.ByPortOverflowLimit,
		ByInterfaceOverflowLimit: summary.ByInterfaceOverflowLimit,
		ByHostOverflowLimit:      summary.ByHostOverflowLimit,
		ByPortOverflow:           summary.ByPortOverflow.Copy(),
		ByInterfaceOverflow:      summary.ByInterfaceOverflow.Copy(),
		ByHostOverflow:           summary.ByHostOverflow.Copy(),
	}
}

func copyPacketCountMap[K comparable](src map[K]*client_telemetry.PacketCounts) map[K]*client_telemetry.PacketCounts {
	if src == nil {
		return nil
	}

	dst := make(map[K]*client_telemetry.PacketCounts, len(src))
	for key, counts := range src {
		dst[key] = counts.Copy()
	}
	return dst
}

func mergePacketCountMap[K comparable](dst, src map[K]*client_telemetry.PacketCounts) map[K]*client_telemetry.PacketCounts {
	if src == nil {
		return dst
	}
	if dst == nil {
		dst = make(map[K]*client_telemetry.PacketCounts, len(src))
	}

	for key, counts := range src {
		if existing, ok := dst[key]; ok {
			mergePacketCounts(existing, counts)
			continue
		}
		dst[key] = counts.Copy()
	}
	return dst
}

func mergePacketCountOverflow(dst **client_telemetry.PacketCounts, src *client_telemetry.PacketCounts) {
	if src == nil {
		return
	}
	if *dst == nil {
		*dst = src.Copy()
		return
	}
	mergePacketCounts(*dst, src)
}
