// SPDX-License-Identifier: Apache-2.0

package apidump

import (
	"context"
	"sync"

	"github.com/akitasoftware/akita-libs/akinet"
	akihttp "github.com/akitasoftware/akita-libs/akinet/http"
	"github.com/akitasoftware/akita-libs/buffer_pool"

	"github.com/postmanlabs/postman-insights-agent/ebpf"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/trace"
)

// startHTTPSeBPFCapture launches the eBPF HTTPS capture pipeline in its own
// goroutine and returns a stop function. The pipeline pushes
// akinet.ParsedNetworkTraffic into the *same* trace.Collector chain that
// pcap.Collect feeds, so downstream redaction / rate limit / backend ship
// logic is unchanged.
//
// On builds without `insights_bpf` (or non-Linux), ebpf.Collect returns
// ebpf.ErrUnsupported immediately; this function logs a warning and returns
// a no-op stop.
//
// `pool` is shared with the pcap pipeline so memview buffers are pooled
// consistently. `collector` is the same chain returned by the per-interface
// collector wiring in apidump.go (rate-limited, redacted, backend-bound).
func startHTTPSeBPFCapture(
	ctx context.Context,
	args *Args,
	pool buffer_pool.BufferPool,
	collector trace.Collector,
	wg *sync.WaitGroup,
) (stop context.CancelFunc) {
	captureCtx, cancel := context.WithCancel(ctx)

	// Channel between the ebpf adapter and the channel→collector pump.
	out := make(chan akinet.ParsedNetworkTraffic, 1024)

	// Same parser factories the pcap path uses. Note: TLS handshake parser
	// is intentionally NOT here \u2014 the eBPF path delivers post-decryption
	// bytes, so the bytes that arrive on `out` are already plaintext HTTP.
	factories := []akinet.TCPParserFactory{
		akihttp.NewHTTPRequestParserFactory(pool),
		akihttp.NewHTTPResponseParserFactory(pool),
	}
	selector := akinet.TCPParserFactorySelector(factories)

	bodyCap := args.HTTPSBodySizeCap
	if bodyCap == 0 {
		bodyCap = 1024
	}

	ebpfArgs := ebpf.Defaults()
	ebpfArgs.MaxCaptureBytes = bodyCap
	// Phase 2 production: trust apidump's discovery to scope what gets probed.
	// The current discovery code attaches to every libssl-loaded PID; namespace
	// filtering is task 6 (deferred). Until that lands we still gate at the
	// command level via --enable-https-capture and at the BPF level via
	// max-capture-bytes.
	ebpfArgs.EnforcePIDAllowlist = false
	ebpfArgs.FactorySelector = selector
	ebpfArgs.Out = out

	// Pump: read parsed traffic, hand to the collector chain.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-captureCtx.Done():
				return
			case pnt, ok := <-out:
				if !ok {
					return
				}
				if err := collector.Process(pnt); err != nil {
					printer.Stderr.Warningf("ebpf: collector.Process: %v\n", err)
				}
			}
		}
	}()

	// Actual eBPF collect loop.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(out)
		if err := ebpf.Collect(captureCtx, ebpfArgs); err != nil {
			printer.Stderr.Warningf("ebpf: capture stopped: %v\n", err)
		}
	}()

	return cancel
}
