// SPDX-License-Identifier: Apache-2.0

// Package apidumpjavatls is the Phase 5a spike command: attach the java_tls
// sys_ioctl kprobe and dump captured plaintext to stdout. Driven for now by
// the C-program harness under test/java-tls-harness/. Phase 5b will replace
// the harness with a real Java agent without changing this command.
package apidumpjavatls

import "github.com/spf13/cobra"

var Cmd = &cobra.Command{
	Use:    "apidump-javatls",
	Short:  "Phase 5a spike: capture decrypted bytes via the Java ioctl bridge",
	Long:   "Phase 5a validation command. NOT for production use. Attaches a kprobe to sys_ioctl gated on fd=0 + cmd=0x0b10b1.",
	Hidden: true,
	RunE:   runE,
}
