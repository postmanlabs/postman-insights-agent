// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package jvm

import "errors"

var errNoControlDir = errors.New("no control directory")

func writeControl(*Process, []byte, bool) error {
	return errors.New("jvm: control files are only supported on Linux")
}

func platformOps(string) (attachOps, error) { return nil, errAttachUnsupported }
