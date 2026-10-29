// SPDX-License-Identifier: Apache-2.0

package jvm

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFlags(t *testing.T) {
	parse := func(args string) jvmFlags { return parseFlags(strings.Fields(args)) }
	assert.Equal(t, jvmFlags{}, parse("-Xmx512m -Dx=y -jar /app/app.jar"))
	assert.True(t, parse("-Xmx1g -XX:+DisableAttachMechanism").attachDisabled)
	assert.False(t, parse("-XX:+DisableAttachMechanism -XX:-DisableAttachMechanism").attachDisabled, "last wins")
	assert.True(t, parse("-XX:-EnableDynamicAgentLoading").dynamicLoadingDisabled)
	assert.True(t, parse("-javaagent:/opt/postman/postman-java-agent.jar=cap=4096").staticAgent)
	assert.True(t, parse("-javaagent:/agents/postman-java-agent.jar").staticAgent)
	assert.False(t, parse("-javaagent:/opt/otel/opentelemetry-javaagent.jar").staticAgent, "another agent")
}

func TestArgsFromCmdline(t *testing.T) {
	cmdline := []byte("java\x00-XX:-DisableAttachMechanism\x00-jar\x00/app.jar\x00")
	environ := []byte("PATH=/bin\x00JAVA_TOOL_OPTIONS=-XX:+DisableAttachMechanism\x00_JAVA_OPTIONS=-Xmx1g\x00")
	args := argsFromCmdline(cmdline, environ)
	assert.Equal(t, []string{"-XX:+DisableAttachMechanism", "-XX:-DisableAttachMechanism", "-Xmx1g"}, args)
	// The command line comes after JAVA_TOOL_OPTIONS, so it wins.
	assert.False(t, parseFlags(args).attachDisabled)
	assert.True(t, parseFlags(argsFromCmdline([]byte("java\x00-jar\x00a.jar\x00"), environ)).attachDisabled)
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

// perfData builds a HotSpot perf data file (format 2) with the given string
// entries, in the given byte order.
func perfData(order binary.ByteOrder, entries map[string]string) []byte {
	b := make([]byte, perfDataPrologueSize)
	copy(b, perfDataMagic)
	if order == binary.LittleEndian {
		b[4] = perfDataLittleEndian
	}
	b[5], b[6] = 2, 0
	order.PutUint32(b[24:], perfDataPrologueSize)
	order.PutUint32(b[28:], uint32(len(entries)+1))
	add := func(name string, dataType byte, data []byte) {
		e := make([]byte, perfDataEntryHeader)
		nameOff := len(e)
		e = append(e, name...)
		e = append(e, 0)
		dataOff := len(e)
		e = append(e, data...)
		for len(e)%8 != 0 {
			e = append(e, 0)
		}
		order.PutUint32(e[0:], uint32(len(e)))
		order.PutUint32(e[4:], uint32(nameOff))
		order.PutUint32(e[8:], uint32(len(data)))
		e[12] = dataType
		order.PutUint32(e[16:], uint32(dataOff))
		b = append(b, e...)
	}
	// A long counter, which is not a string.
	add("sun.os.hrt.frequency", 'J', make([]byte, 8))
	for name, v := range entries {
		data := append([]byte(v), 0)
		data = append(data, make([]byte, 7)...) // vectors are padded past the string
		add(name, 'B', data)
	}
	return b
}

func TestParsePerfData(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		got, err := parsePerfData(perfData(order, map[string]string{
			"java.rt.vmArgs":  "-XX:+DisableAttachMechanism -Xmx1g",
			"java.rt.vmFlags": "",
		}))
		require.NoError(t, err, "%v", order)
		assert.Equal(t, "-XX:+DisableAttachMechanism -Xmx1g", got["java.rt.vmArgs"])
		assert.Contains(t, got, "java.rt.vmFlags")
		assert.NotContains(t, got, "sun.os.hrt.frequency")
	}

	_, err := parsePerfData([]byte("not perf data at all, but long enough"))
	assert.Error(t, err)
	good := perfData(binary.LittleEndian, map[string]string{"java.rt.vmArgs": "-Xmx1g"})
	_, err = parsePerfData(good[:len(good)-30])
	assert.Error(t, err, "truncated")
	bad := append([]byte(nil), good...)
	bad[5] = 3
	_, err = parsePerfData(bad)
	assert.Error(t, err, "unknown version")
}
