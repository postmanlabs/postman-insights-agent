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
// effective arguments. When a flag repeats, the last one wins, as in HotSpot.
func parseFlags(args []string) jvmFlags {
	var f jvmFlags
	for _, a := range args {
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
// (NUL-separated) and the Java options variables of its environment (env, by
// name: attach.JavaOptionVars), in the order HotSpot applies them, for JVMs
// that publish no perf data (-XX:-UsePerfData). Of the command line, only the
// java launcher's options count: what follows the main class, -jar file or
// module is the application's. Argument files are not read.
func argsFromCmdline(cmdline []byte, env map[string]string) []string {
	// JAVA_TOOL_OPTIONS and JDK_JAVA_OPTIONS come before the command line,
	// _JAVA_OPTIONS after it.
	args := splitJavaOptions(env["JAVA_TOOL_OPTIONS"])
	args = append(args, splitJavaOptions(env["JDK_JAVA_OPTIONS"])...)
	if argv := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00"); len(argv) > 1 {
		args = append(args, launcherOptions(argv[1:])...) // argv[0] is the launcher
	}
	return append(args, splitJavaOptions(env["_JAVA_OPTIONS"])...)
}

// splitJavaOptions splits a Java options environment variable into options
// as HotSpot and the java launcher do: at whitespace, except inside single or
// double quotes, which are removed. So -Dmsg='a -XX:-DisableAttachMechanism'
// is one option. A JVM does not start with an unmatched quote; here the rest
// is one option.
func splitJavaOptions(s string) []string {
	var opts []string
	var opt strings.Builder
	inOpt := false
	var quote rune
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				opt.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, inOpt = r, true
		case strings.ContainsRune(" \t\n\v\f\r", r):
			if inOpt {
				opts = append(opts, opt.String())
				opt.Reset()
				inOpt = false
			}
		default:
			opt.WriteRune(r)
			inOpt = true
		}
	}
	if inOpt {
		opts = append(opts, opt.String())
	}
	return opts
}

// launcherOptions returns the options at the start of the java launcher's
// arguments argv: those before the main class (or source file), -jar or
// -m/--module, skipping the values of the options that take the next argument.
func launcherOptions(argv []string) []string {
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "-jar" || a == "-m" || a == "--module" || strings.HasPrefix(a, "--module="):
			return argv[:i]
		case !strings.HasPrefix(a, "-"):
			return argv[:i]
		case launcherOptionsWithValue[a]:
			i++
		}
	}
	return argv
}

// launcherOptionsWithValue are the java launcher's options whose value is the
// next argument (JDK 8 to 25, java.c).
var launcherOptionsWithValue = map[string]bool{
	"-cp": true, "-classpath": true, "--class-path": true,
	"-p": true, "--module-path": true, "--upgrade-module-path": true,
	"--add-modules": true, "--limit-modules": true, "--enable-native-access": true,
	"--add-exports": true, "--add-opens": true, "--add-reads": true, "--patch-module": true,
	"-d": true, "--describe-module": true, "--source": true,
}
