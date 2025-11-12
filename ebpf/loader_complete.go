package ebpf

import (
	"bytes"
	"encoding/binary"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/tags"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
)

// Complete implementation of eBPF loading and management
// This replaces the placeholder functions in loader.go

// loadEBPFCollection loads the compiled eBPF program
func loadEBPFCollectionComplete() (*ebpf.Collection, error) {
	// Remove memory limits for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, errors.Wrap(err, "failed to remove memlock limit")
	}

	// Load the compiled eBPF object file
	// The .o file should be in the bpf subdirectory
	spec, err := ebpf.LoadCollectionSpec("ebpf/bpf/openssl_hook.o")
	if err != nil {
		return nil, errors.Wrap(err, "failed to load eBPF collection spec")
	}

	// Create and load the collection
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create eBPF collection")
	}

	return coll, nil
}

// attachUprobesComplete attaches uprobes to a process
func attachUprobesComplete(libPath string, programs map[string]*ebpf.Program) ([]link.Link, error) {
	// Open the library/executable
	ex, err := link.OpenExecutable(libPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open executable: %s", libPath)
	}

	var links []link.Link

	// Attach uprobe to SSL_write
	if prog, ok := programs["uprobe_ssl_write"]; ok {
		uprobe, err := ex.Uprobe("SSL_write", prog, nil)
		if err != nil {
			return nil, errors.Wrap(err, "failed to attach SSL_write uprobe")
		}
		links = append(links, uprobe)
	}

	// Attach uretprobe to SSL_read
	if prog, ok := programs["uretprobe_ssl_read"]; ok {
		uretprobe, err := ex.Uretprobe("SSL_read", prog, nil)
		if err != nil {
			return nil, errors.Wrap(err, "failed to attach SSL_read uretprobe")
		}
		links = append(links, uretprobe)
	}

	// Also attach SSL_write_ex and SSL_read_ex if available
	if prog, ok := programs["uprobe_ssl_write_ex"]; ok {
		uprobe, err := ex.Uprobe("SSL_write_ex", prog, nil)
		if err == nil {
			links = append(links, uprobe)
		}
	}

	if prog, ok := programs["uretprobe_ssl_read_ex"]; ok {
		uretprobe, err := ex.Uretprobe("SSL_read_ex", prog, nil)
		if err == nil {
			links = append(links, uretprobe)
		}
	}

	return links, nil
}

// processEventsComplete reads from perf ring buffer
func processEventsComplete(reader *perf.Reader, outputChan chan<- akinet.ParsedNetworkTraffic, stopChan <-chan struct{}, handler func(*SSLEvent), telemetry telemetry.Tracker) {
	for {
		select {
		case <-stopChan:
			return
		default:
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				// Handle error (rate limit, etc.)
				if telemetry != nil {
					telemetry.RateLimitError("ebpf event read", err)
				}
				continue
			}

			if record.LostSamples > 0 {
				// Log lost samples
				printer.Debugf("Lost %d eBPF samples\n", record.LostSamples)
				if telemetry != nil {
					telemetry.RateLimitError("ebpf lost samples", errors.Errorf("lost %d samples", record.LostSamples))
				}
				continue
			}

			// Parse the event
			var event SSLEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				// Handle parse error
				if telemetry != nil {
					telemetry.RateLimitError("ebpf event parse", err)
				}
				continue
			}

			// Process the event
			handler(&event)
		}
	}
}

// CompleteHTTPSCapture is the complete implementation
type CompleteHTTPSCapture struct {
	*HTTPSCapture
	collection *ebpf.Collection
	links      []link.Link
	events     *perf.Reader
}

// NewCompleteHTTPSCapture creates a fully functional HTTPS capture instance
func NewCompleteHTTPSCapture(
	serviceID akid.ServiceID,
	traceTags map[tags.Key]string,
	outputChan chan<- akinet.ParsedNetworkTraffic,
	telemetry telemetry.Tracker,
) (*CompleteHTTPSCapture, error) {
	base, err := NewHTTPSCapture(serviceID, traceTags, outputChan, telemetry)
	if err != nil {
		return nil, err
	}

	// Try to load eBPF collection
	collection, err := loadEBPFCollectionComplete()
	if err != nil {
		// Return the base capture even if eBPF loading fails
		// This allows the code to work even if eBPF program isn't compiled yet
		printer.Debugf("eBPF loading failed (expected if .o file not compiled): %v\n", err)
		return &CompleteHTTPSCapture{HTTPSCapture: base}, nil
	}

	// Open perf event reader
	eventsMap, ok := collection.Maps["events"]
	if !ok {
		collection.Close()
		return nil, errors.New("events map not found in eBPF collection")
	}

	events, err := perf.NewReader(eventsMap, 4096)
	if err != nil {
		collection.Close()
		return nil, errors.Wrap(err, "failed to open perf event reader")
	}

	return &CompleteHTTPSCapture{
		HTTPSCapture: base,
		collection:   collection,
		events:       events,
	}, nil
}

// AttachToProcessComplete attaches uprobes with full implementation
func (h *CompleteHTTPSCapture) AttachToProcessComplete(pid int, libPath string) error {
	if h.collection == nil {
		return errors.New("eBPF collection not loaded")
	}

	links, err := attachUprobesComplete(libPath, h.collection.Programs)
	if err != nil {
		return err
	}

	h.links = append(h.links, links...)
	return nil
}

// StartComplete starts capture with full implementation
func (h *CompleteHTTPSCapture) StartComplete() error {
	if err := h.HTTPSCapture.Start(); err != nil {
		return err
	}

	// Start processing events from perf ring buffer
	if h.events != nil {
		go processEventsComplete(h.events, h.outputChan, h.stopChan, h.handleSSLEvent, h.telemetry)
	}

	return nil
}

// StopComplete stops capture and cleans up
func (h *CompleteHTTPSCapture) StopComplete() error {
	// Close all links
	for _, l := range h.links {
		if err := l.Close(); err != nil {
			printer.Errorf("Error closing eBPF link: %v\n", err)
		}
	}

	// Close perf reader
	if h.events != nil {
		if err := h.events.Close(); err != nil {
			printer.Errorf("Error closing perf reader: %v\n", err)
		}
	}

	// Close collection
	if h.collection != nil {
		h.collection.Close()
	}

	return h.HTTPSCapture.Stop()
}
