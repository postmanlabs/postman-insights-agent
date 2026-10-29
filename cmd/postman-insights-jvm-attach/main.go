// SPDX-License-Identifier: Apache-2.0

// postman-insights-jvm-attach loads the Postman Insights Java agent into one
// running JVM. The Insights agent runs it, as the JVM's own user, for each
// JVM it attaches to; it is not meant to be run by hand. It reads one JSON
// request on stdin and writes one JSON result on stdout (see ebpf/jvm/attach).
package main

import (
	"os"

	"github.com/postmanlabs/postman-insights-agent/ebpf/jvm/attach"
)

func main() {
	os.Exit(attach.Main(os.Stdin, os.Stdout))
}
