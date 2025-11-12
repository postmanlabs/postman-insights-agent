package ebpf

import (
	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/tags"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
	"github.com/postmanlabs/postman-insights-agent/trace"
)

// CollectHTTPS runs HTTPS capture alongside the existing pcap-based capture
// This function shows how to integrate eBPF-based HTTPS capture with the
// existing trace collection pipeline.
func CollectHTTPS(
	serviceID akid.ServiceID,
	traceTags map[tags.Key]string,
	stop <-chan struct{},
	collector trace.Collector,
	telemetry telemetry.Tracker,
) error {
	// Create a channel for parsed network traffic from eBPF capture
	parsedChan := make(chan akinet.ParsedNetworkTraffic, 100)

	// Create HTTPS capture instance (using complete implementation)
	httpsCapture, err := NewCompleteHTTPSCapture(
		serviceID,
		traceTags,
		parsedChan,
		telemetry,
	)
	if err != nil {
		return errors.Wrap(err, "failed to create HTTPS capture")
	}
	defer httpsCapture.StopComplete()

	// Discover processes using TLS libraries
	processes, err := discoverTLSProcesses()
	if err != nil {
		printer.Debugf("Failed to discover TLS processes: %v\n", err)
		// Continue anyway - processes may start later
	} else {
		for _, proc := range processes {
			if err := httpsCapture.AttachToProcessComplete(proc.PID, proc.LibPath); err != nil {
				printer.Debugf("Failed to attach to PID %d: %v\n", proc.PID, err)
				// Continue with other processes
				continue
			}
			printer.Debugf("Attached eBPF uprobes to PID %d (%s)\n", proc.PID, proc.Name)
		}
	}

	// Start HTTPS capture
	if err := httpsCapture.StartComplete(); err != nil {
		return errors.Wrap(err, "failed to start HTTPS capture")
	}

	// Process parsed network traffic from eBPF capture
	// This feeds into the same collector pipeline as pcap-based capture
	go func() {
		for t := range parsedChan {
			// Process through the same collector chain as pcap traffic
			if err := collector.Process(t); err != nil {
				telemetry.RateLimitError("ebpf collector process", err)
			}
			t.Content.ReleaseBuffers()
		}
	}()

	// Wait for stop signal
	<-stop

	return nil
}

// discoverTLSProcesses scans running processes to find those using TLS libraries
func discoverTLSProcesses() ([]ProcessInfo, error) {
	return DiscoverTLSProcesses()
}

// ProcessInfo represents a process using TLS libraries
type ProcessInfo struct {
	PID     int
	LibPath string // Path to libssl.so or equivalent
	Name    string // Process name
}

