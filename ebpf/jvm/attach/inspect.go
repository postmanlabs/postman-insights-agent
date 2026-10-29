// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"errors"
	"strings"
)

// maxPerfDataSize bounds how much of a perf data file is read (HotSpot's
// default is 32 KiB).
const maxPerfDataSize = 1 << 20

// perfDataEntries returns the PerfDataKeys entries of the perf data file
// content b, which must have the JVM's effective arguments (java.rt.vmArgs).
func perfDataEntries(b []byte) (map[string]string, error) {
	all, err := parsePerfData(b)
	if err != nil {
		return nil, err
	}
	if _, ok := all["java.rt.vmArgs"]; !ok {
		return nil, errors.New("perf data without java.rt.vmArgs")
	}
	out := make(map[string]string, len(PerfDataKeys))
	for _, k := range PerfDataKeys {
		if v, ok := all[k]; ok {
			out[k] = v
		}
	}
	return out, nil
}

// javaOptions returns the JavaOptionVars set in environ, a process's
// environment (NUL-separated KEY=VALUE). Of a variable set twice, the first
// counts, as getenv returns it.
func javaOptions(environ []byte) map[string]string {
	out := map[string]string{}
	for kv := range strings.SplitSeq(string(environ), "\x00") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if _, seen := out[k]; seen {
			continue
		}
		for _, name := range JavaOptionVars {
			if k == name {
				out[k] = v
			}
		}
	}
	return out
}
