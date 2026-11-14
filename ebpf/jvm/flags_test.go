package jvm

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseFlags(t *testing.T) {
	parse := func(args string) jvmFlags { return parseFlags(strings.Fields(args)) }
	assert.Equal(t, jvmFlags{}, parse("-Xmx512m -Dx=y -jar /app/app.jar"))
	assert.True(t, parse("-Xmx1g -XX:+DisableAttachMechanism").attachDisabled)
	assert.False(t, parse("-XX:+DisableAttachMechanism -XX:-DisableAttachMechanism").attachDisabled, "last wins")
	assert.True(t, parse("-XX:-EnableDynamicAgentLoading").dynamicLoadingDisabled)
	assert.True(t, parse("-javaagent:/opt/postman/postman-insights-java-agent.jar=cap=4096").staticAgent)
	assert.True(t, parse("-javaagent:/agents/postman-insights-java-agent.jar").staticAgent)
	assert.True(t, parse("-javaagent:/agents/postman-java-agent.jar").staticAgent, "the v0.42.0-rc1 name")
	assert.False(t, parse("-javaagent:/opt/otel/opentelemetry-javaagent.jar").staticAgent, "another agent")
}

func TestArgsFromCmdline(t *testing.T) {
	cmdline := []byte("java\x00-XX:-DisableAttachMechanism\x00-jar\x00/app.jar\x00")
	env := map[string]string{"JAVA_TOOL_OPTIONS": "-XX:+DisableAttachMechanism", "_JAVA_OPTIONS": "-Xmx1g"}
	args := argsFromCmdline(cmdline, env)
	assert.Equal(t, []string{"-XX:+DisableAttachMechanism", "-XX:-DisableAttachMechanism", "-Xmx1g"}, args)
	// The command line comes after JAVA_TOOL_OPTIONS, so it wins.
	assert.False(t, parseFlags(args).attachDisabled)
	assert.True(t, parseFlags(argsFromCmdline([]byte("java\x00-jar\x00a.jar\x00"), env)).attachDisabled)
}

// Java options in the environment are split as HotSpot splits them: quotes
// keep an option with spaces whole.
func TestSplitJavaOptions(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"  -Xmx1g\t-Dx=y \n", []string{"-Xmx1g", "-Dx=y"}},
		{`-Dmsg="a -XX:-DisableAttachMechanism" -Xmx1g`, []string{"-Dmsg=a -XX:-DisableAttachMechanism", "-Xmx1g"}},
		{`-Dmsg='say "hi"' x`, []string{`-Dmsg=say "hi"`, "x"}},
		{`"-Dquoted whole" -Dmid="x"y`, []string{"-Dquoted whole", "-Dmid=xy"}},
		{`-Dempty="" -Dopen="a b`, []string{"-Dempty=", "-Dopen=a b"}},
	} {
		assert.Equal(t, tc.want, splitJavaOptions(tc.in), "%q", tc.in)
	}

	env := map[string]string{"JAVA_TOOL_OPTIONS": "-XX:+DisableAttachMechanism -Dmsg='x -XX:-DisableAttachMechanism y'"}
	assert.True(t, parseFlags(argsFromCmdline([]byte("java\x00-jar\x00a.jar\x00"), env)).attachDisabled,
		"a quoted option is not a flag")
}

// The application's arguments, after the main class, -jar file or module,
// are not the JVM's, nor are the values of options that take one; an
// argument with spaces stays one argument.
func TestArgsFromCmdlineApplicationArgs(t *testing.T) {
	disabled := func(argv ...string) bool {
		t.Helper()
		cmdline := []byte(strings.Join(argv, "\x00") + "\x00")
		return parseFlags(argsFromCmdline(cmdline, nil)).attachDisabled
	}
	const off, on = "-XX:+DisableAttachMechanism", "-XX:-DisableAttachMechanism"
	assert.True(t, disabled("java", off, "-jar", "app.jar", on), "after -jar")
	assert.True(t, disabled("java", off, "com.example.Main", on), "after the main class")
	assert.True(t, disabled("java", off, "-m", "app/com.example.Main", on), "after -m")
	assert.True(t, disabled("java", off, "--module=app/com.example.Main", on), "after --module=")
	assert.True(t, disabled("java", off, "Main.java", on), "after a source file")
	assert.True(t, disabled("java", off, "-cp", "/app/lib/*", "com.example.Main", on), "after -cp and its value")
	assert.False(t, disabled("java", off, "-cp", "/app", on, "com.example.Main"), "an option after -cp's value")
	assert.False(t, disabled("java", off, "--add-opens", "java.base/java.lang=ALL-UNNAMED", on, "-jar", "a.jar"))
	assert.True(t, disabled("java", off, "-Dmsg=a "+on, "-jar", "a.jar"), "inside another argument")
	assert.False(t, disabled("java"), "the launcher alone")
}

func TestPerfDataAttach(t *testing.T) {
	on, known := perfDataAttach(map[string]string{"sun.rt.jvmCapabilities": "0100"})
	assert.True(t, known)
	assert.False(t, on, "-XX:+DisableAttachMechanism")
	on, known = perfDataAttach(map[string]string{"sun.rt.jvmCapabilities": "1000"})
	assert.True(t, known)
	assert.True(t, on)
	_, known = perfDataAttach(map[string]string{"java.rt.vmArgs": ""})
	assert.False(t, known)
}
