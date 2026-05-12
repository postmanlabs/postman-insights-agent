// SPDX-License-Identifier: Apache-2.0

//go:build linux && insights_bpf

package apidumpebpf

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
	"github.com/postmanlabs/postman-insights-agent/printer"
)

var (
	flagDuration time.Duration
	flagMaxBytes uint32
)

func init() {
	Cmd.Flags().DurationVar(&flagDuration, "duration", 0, "Stop after this duration (0 = run until SIGINT)")
	Cmd.Flags().Uint32Var(&flagMaxBytes, "max-capture-bytes", 1024, "Maximum plaintext bytes captured per event")
}

func runE(cmd *cobra.Command, _ []string) error {
	ctx, cancel := signalCtx(cmd.Context())
	defer cancel()

	if flagDuration > 0 {
		var c context.CancelFunc
		ctx, c = context.WithTimeout(ctx, flagDuration)
		defer c()
	}

	// Set up the same akinet parser factories the pcap path uses.
	pool, err := buffer_pool.MakeBufferPool(64*1024*1024, 4096)
	if err != nil {
		return fmt.Errorf("buffer pool: %w", err)
	}
	factories := []akinet.TCPParserFactory{
		akihttp.NewHTTPRequestParserFactory(pool),
		akihttp.NewHTTPResponseParserFactory(pool),
	}
	selector := akinet.TCPParserFactorySelector(factories)

	// Output channel: simple stdout dumper for the spike.
	out := make(chan akinet.ParsedNetworkTraffic, 256)
	go func() {
		for pnt := range out {
			switch c := pnt.Content.(type) {
			case akinet.HTTPRequest:
				printer.Stdout.Infof("REQ  pid? method=%s url=%v\n", c.Method, c.URL)
			case akinet.HTTPResponse:
				printer.Stdout.Infof("RESP pid? status=%d\n", c.StatusCode)
			}
		}
	}()

	args := ebpf.Defaults()
	args.MaxCaptureBytes = flagMaxBytes
	args.FactorySelector = selector
	args.Out = out

	printer.Stderr.Infof("Starting eBPF HTTPS capture spike (duration=%v, max-bytes=%d)\n",
		flagDuration, flagMaxBytes)

	if err := ebpf.Collect(ctx, args); err != nil {
		return err
	}
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
