// SPDX-License-Identifier: Apache-2.0

//go:build !linux || !insights_bpf

package apidumpjavatls

import (
	"errors"

	"github.com/spf13/cobra"
)

func runE(_ *cobra.Command, _ []string) error {
	return errors.New("apidump-javatls: not compiled in; rebuild with -tags insights_bpf on Linux")
}
