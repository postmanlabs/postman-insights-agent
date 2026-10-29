// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package attach

// Run is only supported on Linux.
func Run(Request) Result {
	return failed(ReasonBadRequest, false, "attach is only supported on Linux")
}
