// SPDX-License-Identifier: Apache-2.0

// Package apidumpebpf is a developer tool for credential-free eBPF capture.
//
// It attaches libssl uprobes and prints REQ/RESP lines to stdout — no Postman
// API key required. Useful for local smoke-testing eBPF capture without a
// backend connection.
//
// For production use (sending to Postman), use the main apidump command:
//
//	postman-insights-agent apidump --enable-https-capture
//
// Build:
//
//	go build -tags insights_bpf -o bin/postman-insights-agent .
//	sudo ./bin/postman-insights-agent apidump-ebpf --duration 60s
//
// Requires Linux ≥ 5.8 with BTF, CAP_BPF + CAP_PERFMON (or root).

package apidumpebpf

import "github.com/spf13/cobra"

// Cmd is hidden from --help (it is a dev tool, not a user-facing command).
// On non-insights_bpf builds, runE returns a friendly error.
var Cmd = &cobra.Command{
	Use:   "apidump-ebpf",
	Short: "Dev: credential-free eBPF capture — logs REQ/RESP to stdout",
	Long: `Developer tool for local eBPF capture testing without backend credentials.
Attaches libssl uprobes for OpenSSL-based runtimes. All output goes to stdout.

For production traffic capture, use:
  postman-insights-agent apidump --enable-https-capture`,
	RunE: runE,
}
