// SPDX-License-Identifier: Apache-2.0

package jvm

import "strings"

// jvmFlags is what the JVM's effective arguments say about attaching.
type jvmFlags struct {
	// attachDisabled: -XX:+DisableAttachMechanism. Signalling such a JVM
	// prints a thread dump into the application's log and attaches nothing.
	attachDisabled bool
	// dynamicLoadingDisabled: -XX:-EnableDynamicAgentLoading (JDK 21+),
	// which refuses agents loaded by attach.
	dynamicLoadingDisabled bool
	// staticAgent: the Postman Java agent is loaded at start through
	// -javaagent, so there is nothing to attach.
	staticAgent bool
}

// parseFlags reads the arguments that matter for attaching from a JVM's
// effective arguments, separated by whitespace. When a flag repeats, the
// last one wins, as in HotSpot.
func parseFlags(args string) jvmFlags {
	var f jvmFlags
	for _, a := range strings.Fields(args) {
		switch a {
		case "-XX:+DisableAttachMechanism":
			f.attachDisabled = true
		case "-XX:-DisableAttachMechanism":
			f.attachDisabled = false
		case "-XX:-EnableDynamicAgentLoading":
			f.dynamicLoadingDisabled = true
		case "-XX:+EnableDynamicAgentLoading":
			f.dynamicLoadingDisabled = false
		default:
			if jar, ok := strings.CutPrefix(a, "-javaagent:"); ok {
				jar, _, _ = strings.Cut(jar, "=")
				if strings.HasSuffix(jar, "postman-java-agent.jar") {
					f.staticAgent = true
				}
			}
		}
	}
	return f
}

// argsFromCmdline returns a JVM's arguments from its command line
// (NUL-separated) and the Java options in its environment (NUL-separated
// KEY=VALUE), in the order HotSpot applies them, for JVMs that publish no perf
// data (-XX:-UsePerfData). Argument files are not read.
func argsFromCmdline(cmdline, environ []byte) string {
	env := map[string]string{}
	for kv := range strings.SplitSeq(string(environ), "\x00") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	// JAVA_TOOL_OPTIONS and JDK_JAVA_OPTIONS come before the command line,
	// _JAVA_OPTIONS after it.
	parts := []string{env["JAVA_TOOL_OPTIONS"], env["JDK_JAVA_OPTIONS"]}
	parts = append(parts, strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")...)
	parts = append(parts, env["_JAVA_OPTIONS"])
	return strings.Join(parts, " ")
}
