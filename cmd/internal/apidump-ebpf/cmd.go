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
	Short: "Phase 1 spike: capture HTTPS traffic via eBPF uprobes on libssl",
	Long: `Standalone HTTPS capture spike. Attaches libssl uprobes to every
process on the host that has libssl mapped, dumps decrypted bytes to stdout,
and emits per-PID counters.

This command exists ONLY for Phase 1 validation. The production path is
'postman-insights-agent apidump --enable-https-capture'.

See docs/https-capture-design.md for the full design.`,
	RunE: runE,
}
