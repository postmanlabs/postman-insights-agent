// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

// An Inspection carries only the PerfDataKeys entries, and only from perf
// data with the JVM's arguments.
func TestPerfDataEntries(t *testing.T) {
	got, err := perfDataEntries(perfData(binary.LittleEndian, map[string]string{
		"java.rt.vmArgs":         "-Xmx1g",
		"sun.rt.jvmCapabilities": "1000",
		"java.property.user.dir": "/app",
	}))
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"java.rt.vmArgs": "-Xmx1g", "sun.rt.jvmCapabilities": "1000"}, got)

	_, err = perfDataEntries(perfData(binary.LittleEndian, map[string]string{"java.rt.vmFlags": ""}))
	assert.Error(t, err, "no java.rt.vmArgs")
}

// Only the Java options variables leave the helper, and of one set twice the
// first, as getenv returns it.
func TestJavaOptions(t *testing.T) {
	environ := []byte("PATH=/bin\x00DB_PASSWORD=secret\x00JAVA_TOOL_OPTIONS=-Xmx1g\x00" +
		"JAVA_TOOL_OPTIONS=-Xmx2g\x00_JAVA_OPTIONS=\x00JDK_JAVA_OPTIONS=-Dx=a=b\x00noequals\x00")
	assert.Equal(t, map[string]string{
		"JAVA_TOOL_OPTIONS": "-Xmx1g",
		"JDK_JAVA_OPTIONS":  "-Dx=a=b",
		"_JAVA_OPTIONS":     "",
	}, javaOptions(environ))
	assert.Empty(t, javaOptions(nil))
}
