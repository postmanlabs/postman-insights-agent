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
	"github.com/postmanlabs/postman-insights-agent/ebpf/discovery"
	"github.com/postmanlabs/postman-insights-agent/ebpf/events"
	"github.com/postmanlabs/postman-insights-agent/ebpf/loader"
	"github.com/postmanlabs/postman-insights-agent/ebpf/uprobes"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

var (
	flagDuration         time.Duration
	flagMaxBytes         uint32
	flagRateCap          uint32
	flagStatsEvery       time.Duration
	flagTargetNamespaces []string
)

func init() {
	Cmd.Flags().DurationVar(&flagDuration, "duration", 0, "Stop after this duration (0 = run until SIGINT)")
	Cmd.Flags().Uint32Var(&flagMaxBytes, "max-capture-bytes", 1024, "Maximum plaintext bytes captured per event")
	Cmd.Flags().Uint32Var(&flagRateCap, "rate-cap-per-sec", 0, "Per-PID rate cap (events/sec). 0 disables rate limiting.")
	Cmd.Flags().DurationVar(&flagStatsEvery, "stats-every", 0, "If >0, log BPF counter stats every interval.")
	Cmd.Flags().StringSliceVar(&flagTargetNamespaces, "target-namespaces", nil, "Restrict capture to PIDs whose K8s namespace is in this list. Requires running in a kube cluster.")
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
			flow := fmt.Sprintf("%v:%d -> %v:%d (%s)", pnt.SrcIP, pnt.SrcPort, pnt.DstIP, pnt.DstPort, pnt.Interface)
			switch c := pnt.Content.(type) {
			case akinet.HTTPRequest:
				printer.Stdout.Infof("REQ  %s method=%s url=%v\n", flow, c.Method, c.URL)
			case akinet.HTTPResponse:
				printer.Stdout.Infof("RESP %s status=%d\n", flow, c.StatusCode)
			}
		}
	}()

	args := ebpf.Defaults()
	args.MaxCaptureBytes = flagMaxBytes
	args.FactorySelector = selector
	args.Out = out
	args.RateCapPerSec = flagRateCap
	// Auto-detect /host/proc for DaemonSet deployments.
	if _, err := os.Stat("/host/proc/self"); err == nil {
		args.ProcRoot = "/host/proc"
		printer.Stderr.Infof("Using /host/proc as proc root.\n")
	}

	// Namespace filtering for the spike. In production this is plumbed via
	// apidump --https-target-namespaces; we mirror it here so the same demo
	// flow works without backend credentials.
	if len(flagTargetNamespaces) > 0 {
		resolver, err := discovery.NewKubeNamespaceResolver(args.ProcRoot, "/proc")
		if err != nil {
			printer.Stderr.Warningf("--target-namespaces set but kube client init failed: %v; falling back to no filter\n", err)
		} else {
			allowed := make(map[string]struct{}, len(flagTargetNamespaces))
			for _, ns := range flagTargetNamespaces {
				allowed[ns] = struct{}{}
			}
			printer.Stderr.Infof("Namespace filtering enabled: allowed = %v\n", flagTargetNamespaces)
			stop := make(chan struct{})
			go func() { <-ctx.Done(); close(stop); resolver.Close() }()
			go resolver.RunRefresh(stop, 30*time.Second)
			// NOTE: Discovery scans the agent's own /proc (not args.ProcRoot)
			// so the PIDs it returns are usable for perf_event_open which uses
			// the agent's PID namespace.
			args.Discovery = discovery.WatchWith(ctx, discovery.WatchOpts{
				Interval:          2 * time.Second,
				NamespaceResolver: resolver,
				AllowedNamespaces: allowed,
			})
		}
	}

	if flagStatsEvery > 0 {
		args.HookLoader = func(
			ldr *loader.Loader, _ *ebpf.Thermostat,
			_ *uprobes.Manager, a *events.Adapter,
		) {
			go func() {
				t := time.NewTicker(flagStatsEvery)
				defer t.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-t.C:
						em, _ := ldr.ReadCounter(loader.CounterEventsEmitted)
						dr, _ := ldr.ReadCounter(loader.CounterEventsDropped)
						rd, _ := ldr.ReadCounter(loader.CounterReadFailed)
						rc, _ := ldr.ReadCounter(4) // rate-cap drops
						by, _ := ldr.ReadCounter(loader.CounterBytesCaptured)
						sf, _ := ldr.ReadCounter(5) // SSL_set_fd calls
						fdok, _ := ldr.ReadCounter(6) // events with fd>=0
						var resStats string
						if a != nil && a.Resolver != nil {
							d := &a.Resolver.Debug
							resStats = fmt.Sprintf(" resolver_hit=%d miss=%d inode_ok=%d inode_fail=%d",
								d.InodeHit.Load(), d.InodeMiss.Load(),
								d.InodeReadOK.Load(), d.InodeReadFail.Load())
						}
						printer.Stderr.Infof(
							"stats: emitted=%d ringbuf_drops=%d ratecap_drops=%d read_fail=%d bytes=%d ssl_set_fd=%d events_with_fd=%d%s\n",
							em, dr, rc, rd, by, sf, fdok, resStats)
					}
				}
			}()
		}
	}

	printer.Stderr.Infof("Starting eBPF HTTPS capture spike (duration=%v, max-bytes=%d, rate-cap=%d)\n",
		flagDuration, flagMaxBytes, flagRateCap)

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
