// SPDX-License-Identifier: Apache-2.0

// Package apidumpgotls is a one-off spike command for Phase 3 of the HTTPS
// capture program: attach Go crypto/tls uprobes to a target binary and dump
// captured plaintext to stdout. Mirrors apidump-ebpf for the libssl path.
package apidumpgotls

import "github.com/spf13/cobra"

// Cmd is the cobra command exposed by the agent CLI.
var Cmd = &cobra.Command{
	Use:    "apidump-gotls",
	Short:  "Phase 3 spike: capture HTTPS from Go binaries via crypto/tls uprobes",
	Long:   "Phase 3 validation command. NOT for production use. Attaches uprobes to crypto/tls.(*Conn).Write in a target Go binary.",
	Hidden: true,
	RunE:   runE,
}
