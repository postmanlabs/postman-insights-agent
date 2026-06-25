// Package apidumpebpf is the Phase 1 spike command for HTTPS capture.
//
// This is a STANDALONE entry point used to validate the eBPF subsystem end
// to end without touching the main `apidump` command. Once the spike passes
// its exit criteria (see docs/https-capture-design.md §9 Phase 1), Phase 2
// integrates `ebpf.Collect` into the main apidump path via the
// `--enable-https-capture` flag, and this command is removed.
//
// Build & run:
//
//	go build -tags insights_bpf -o bin/apidump-ebpf ./cmd/internal/apidump-ebpf
//	sudo ./bin/apidump-ebpf --duration 60s
//
// Requires Linux ≥ 5.8 with BTF, and CAP_BPF + CAP_PERFMON (or root).

package apidumpebpf

import "github.com/spf13/cobra"

// Cmd is the cobra command registered by main, when the binary is built
// with -tags insights_bpf. Without the tag, Cmd is a stub that prints an
// informative error.
var Cmd = &cobra.Command{
	Use:   "apidump-ebpf",
	Short: "Spike: HTTPS capture via eBPF (libssl uprobes + optional Java TLS)",
	Long: `Standalone HTTPS capture spike for Kind/dev. Attaches libssl uprobes
for OpenSSL-based runtimes and, with --enable-javatls, the java_tls kprobe
for JVM traffic. All REQ/RESP lines go to stdout (one log stream per pod).

Production path: postman-insights-agent apidump --enable-https-capture on
the node DaemonSet. See docs/https-capture-design.md.`,
	RunE: runE,
}
