// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package apidumpjavatls

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	akihttp "github.com/akitasoftware/akita-libs/akinet/http"
	"github.com/akitasoftware/akita-libs/buffer_pool"
	"github.com/spf13/cobra"

	"github.com/postmanlabs/postman-insights-agent/ebpf"
	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

var (
	flagDuration time.Duration
	flagPIDs     []uint
	flagMaxBytes uint32
	flagEnforce  bool
)

func init() {
	Cmd.Flags().DurationVar(&flagDuration, "duration", 0, "Stop after this duration (0 = SIGINT)")
	Cmd.Flags().UintSliceVar(&flagPIDs, "pid", nil, "Restrict capture to these PIDs (repeatable; implies --enforce-allowlist)")
	Cmd.Flags().Uint32Var(&flagMaxBytes, "max-capture-bytes", 1024, "Max plaintext bytes per event (≤ 1024)")
	Cmd.Flags().BoolVar(&flagEnforce, "enforce-allowlist", false, "Only emit events for PIDs in --pid (default: trace any PID issuing the magic ioctl)")
}

func runE(cmd *cobra.Command, _ []string) error {
	ctx, cancel := signalCtx(cmd.Context())
	defer cancel()
	if flagDuration > 0 {
		var c context.CancelFunc
		ctx, c = context.WithTimeout(ctx, flagDuration)
		defer c()
	}

	if len(flagPIDs) > 0 {
		flagEnforce = true
	}

	pool, err := buffer_pool.MakeBufferPool(16*1024*1024, 4096)
	if err != nil {
		return fmt.Errorf("buffer pool: %w", err)
	}
	factories := []akinet.TCPParserFactory{
		akihttp.NewHTTPRequestParserFactory(pool),
		akihttp.NewHTTPResponseParserFactory(pool),
	}
	selector := akinet.TCPParserFactorySelector(factories)

	debugRaw := os.Getenv("JAVATLS_DEBUG_RAW") != ""
	if debugRaw {
		printer.Stderr.Infof("JAVATLS_DEBUG_RAW set — raw bytes will be dumped\n")
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

	collector, err := ebpf.NewJavaTLSCollectorWithRawTap(flagMaxBytes, flagEnforce, adapter, debugRaw)
	if err != nil {
		return fmt.Errorf("javatls collector: %w", err)
	}
	defer collector.Close()

	for _, pid := range flagPIDs {
		if err := collector.AddTargetPID(uint32(pid)); err != nil {
			return fmt.Errorf("allowlist pid %d: %w", pid, err)
		}
	}

	if err := collector.Attach(); err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	printer.Stderr.Infof("Attached java_tls kprobe (enforce_allowlist=%v, pids=%v)\n", flagEnforce, flagPIDs)

	// Periodic stats so the demo shows liveness.
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				printer.Stderr.Infof("javatls-stats: emitted=%d ringbuf_drops=%d read_fail=%d bytes=%d bad_cmd=%d\n",
					collector.CounterEmitted(),
					collector.CounterRingbufDrops(),
					collector.CounterReadFailed(),
					collector.CounterBytes(),
					collector.CounterBadCmd())
			}
		}
	}()

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
