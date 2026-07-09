// SPDX-License-Identifier: Apache-2.0

//go:build !linux || !insights_bpf

package apidumpebpf

import (
	"errors"

	"github.com/spf13/cobra"
)

func runE(_ *cobra.Command, _ []string) error {
	return errors.New("apidump-ebpf requires Linux ≥ 5.8 and a build with -tags insights_bpf; " +
		"see docs/https-capture-design.md for build instructions")
}
