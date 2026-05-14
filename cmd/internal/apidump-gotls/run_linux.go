// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package apidumpgotls

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	akihttp "github.com/akitasoftware/akita-libs/akinet/http"
	akihttp2 "github.com/akitasoftware/akita-libs/akinet/http2"
	"github.com/akitasoftware/akita-libs/buffer_pool"
	"github.com/spf13/cobra"

	"github.com/postmanlabs/postman-insights-agent/ebpf"
	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

var (
	flagDuration time.Duration
	flagPID      uint32
	flagBinary   string
	flagMaxBytes uint32
)

func init() {
	Cmd.Flags().DurationVar(&flagDuration, "duration", 0, "Stop after this duration (0 = SIGINT)")
	Cmd.Flags().Uint32Var(&flagPID, "pid", 0, "Target PID (required)")
	Cmd.Flags().StringVar(&flagBinary, "binary", "", "Path to the Go binary (default: /proc/<pid>/exe)")
	Cmd.Flags().Uint32Var(&flagMaxBytes, "max-capture-bytes", 1024, "Max plaintext bytes per event")
	_ = Cmd.MarkFlagRequired("pid")
}

func runE(cmd *cobra.Command, _ []string) error {
	if flagBinary == "" {
		flagBinary = fmt.Sprintf("/proc/%d/exe", flagPID)
	}

	ctx, cancel := signalCtx(cmd.Context())
	defer cancel()
	if flagDuration > 0 {
		var c context.CancelFunc
		ctx, c = context.WithTimeout(ctx, flagDuration)
		defer c()
	}

	pool, err := buffer_pool.MakeBufferPool(16*1024*1024, 4096)
	if err != nil {
		return fmt.Errorf("buffer pool: %w", err)
	}
	factories := []akinet.TCPParserFactory{
		akihttp.NewHTTPRequestParserFactory(pool),
		akihttp.NewHTTPResponseParserFactory(pool),
		// HTTP/2 preface detection — fires when Go's net/http upgraded the
		// connection to h2. Full HTTP/2 frame decoding is a Phase 3 follow-up;
		// for now we get "saw h2 preface" markers + raw binary in the
		// per-flow dumps. Clients can force HTTP/1.1 via `curl --http1.1`.
		akihttp2.NewHTTP2PrefaceParserFactory(),
	}
	selector := akinet.TCPParserFactorySelector(factories)

	debugRaw := os.Getenv("GOTLS_DEBUG_RAW") != ""
	if debugRaw {
		printer.Stderr.Infof("GOTLS_DEBUG_RAW set — raw bytes will be dumped\n")
	}

	out := make(chan akinet.ParsedNetworkTraffic, 256)
	go func() {
		for pnt := range out {
			switch c := pnt.Content.(type) {
			case akinet.HTTPRequest:
				printer.Stdout.Infof("REQ  pid=%s method=%s url=%v\n", pnt.Interface, c.Method, c.URL)
			case akinet.HTTPResponse:
				printer.Stdout.Infof("RESP pid=%s status=%d\n", pnt.Interface, c.StatusCode)
			}
		}
	}()

	adapter := events.NewAdapter(selector, out)

	collector, err := ebpf.NewGoTLSCollectorWithRawTap(flagMaxBytes, adapter, debugRaw)
	if err != nil {
		return fmt.Errorf("gotls collector: %w", err)
	}
	defer collector.Close()

	if err := collector.Attach(ebpf.GoTLSTarget{
		PID:        flagPID,
		BinaryPath: flagBinary,
	}); err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	printer.Stderr.Infof("Attached gotls write uprobe to pid=%d binary=%s\n", flagPID, flagBinary)

	// Periodic stats dump so the demo shows liveness even when bytes
	// haven't yet flowed through.
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				em := collector.CounterEmitted()
				dr := collector.CounterDropped()
				rd := collector.CounterReadFailed()
				by := collector.CounterBytes()
				printer.Stderr.Infof("gotls-stats: emitted=%d ringbuf_drops=%d read_fail=%d bytes=%d\n",
					em, dr, rd, by)
			}
		}
	}()

	// Reader pump.
	monoEpoch := time.Now()
	collector.Run(ctx, monoEpoch)
	return nil
}

func signalCtx(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sig:
			cancel()
		case <-ctx.Done():
		}
		signal.Stop(sig)
	}()
	return ctx, cancel
}
