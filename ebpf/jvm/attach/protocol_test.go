// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"bytes"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeJVM serves one attach request on a unix socket, recording it, and
// replies with reply.
func fakeJVM(t *testing.T, reply string) (sock string, got chan string) {
	t.Helper()
	sock = filepath.Join(t.TempDir(), "attach.sock")
	l, err := net.Listen("unix", sock)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	got = make(chan string, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// A request is five NUL-terminated fields.
		var req bytes.Buffer
		buf := make([]byte, 1)
		for nuls := 0; nuls < 5; {
			if _, err := c.Read(buf); err != nil {
				return
			}
			req.WriteByte(buf[0])
			if buf[0] == 0 {
				nuls++
			}
		}
		got <- req.String()
		_, _ = io.WriteString(c, reply)
	}()
	return sock, got
}

func TestExecuteLoad(t *testing.T) {
	sock, got := fakeJVM(t, "0\nreturn code: 0\n")
	out, err := execute(sock, time.Second, "load", "instrument", "false", "/tmp/a.jar=cap=4096")
	require.NoError(t, err)
	assert.Equal(t, "1\x00load\x00instrument\x00false\x00/tmp/a.jar=cap=4096\x00", <-got)
	assert.NoError(t, loadResult(out))
}

func TestExecuteFewerArguments(t *testing.T) {
	sock, got := fakeJVM(t, "0\n#Tue Oct 14\njava.version=21\n")
	out, err := execute(sock, time.Second, "properties")
	require.NoError(t, err)
	assert.Equal(t, "1\x00properties\x00\x00\x00\x00", <-got, "always exactly three arguments")
	assert.Equal(t, "21", property(out, "java.version"))
}

func TestExecuteErrorStatus(t *testing.T) {
	sock, _ := fakeJVM(t, "101\nOperation not recognized\n")
	_, err := execute(sock, time.Second, "frobnicate")
	var st *errStatus
	require.ErrorAs(t, err, &st)
	assert.Equal(t, 101, st.code)
	assert.Contains(t, err.Error(), "Operation not recognized")
}

func TestExecuteNoListener(t *testing.T) {
	_, err := execute(filepath.Join(t.TempDir(), "nothing"), time.Second, "properties")
	assert.Error(t, err)
}

func TestLoadResult(t *testing.T) {
	assert.NoError(t, loadResult("return code: 0\n"), "JDK 9+")
	assert.NoError(t, loadResult("0\n"), "JDK 8")
	assert.ErrorContains(t, loadResult("return code: 100\n"), "100")
	assert.ErrorContains(t, loadResult("102\n"), "102")
	assert.Error(t, loadResult(""))
	assert.Error(t, loadResult("Agent JAR not found or no Agent-Class attribute"))
}

func TestProperty(t *testing.T) {
	out := strings.Join([]string{
		"#Tue Oct 14 10:00:00 UTC 2026",
		"java.vendor=Eclipse Adoptium",
		`postman.insights.agent.failed=0.1.0\: java.lang.NoClassDefFoundError\: xé`,
		"postman.insights.agent.version=0.1.0",
		"",
	}, "\r\n")
	assert.Equal(t, "0.1.0", property(out, "postman.insights.agent.version"))
	assert.Equal(t, "0.1.0: java.lang.NoClassDefFoundError: xé", property(out, "postman.insights.agent.failed"))
	assert.Equal(t, "", property(out, "postman.insights.agent"), "a prefix is not a key")
	assert.Equal(t, "", property(out, "missing"))
}

func TestStartTimeFromStat(t *testing.T) {
	got, err := StartTimeFromStat([]byte("42 (a (b) c) S 1 42 42 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 123456 0 0\n"))
	require.NoError(t, err)
	assert.Equal(t, uint64(123456), got)
	_, err = StartTimeFromStat([]byte("42 (java) S 1"))
	assert.Error(t, err)
}

func TestMainBadRequest(t *testing.T) {
	defer func(r func(Request) Result) { run = r }(run)
	run = func(Request) Result {
		t.Error("performed a request that did not decode")
		return Result{Outcome: Attached}
	}

	var out bytes.Buffer
	// Complete, but with a field the helper does not know.
	assert.Equal(t, 2, Main(strings.NewReader(`{"version":1,"pid":1,"start_time":1,"nspid":1,"jar_path":"/x","surprise":true}`), &out))
	assert.Contains(t, out.String(), `"reason":"bad_request"`)

	// Complete, but followed by more data.
	out.Reset()
	assert.Equal(t, 2, Main(strings.NewReader(`{"version":1,"pid":1,"start_time":1,"nspid":1,"jar_path":"/x"} {}`), &out))
	assert.Contains(t, out.String(), `"reason":"bad_request"`)

	out.Reset()
	assert.Equal(t, 2, Main(strings.NewReader(`{"version":1,"surprise":true}`), &out))
	assert.Contains(t, out.String(), `"reason":"bad_request"`)

	out.Reset()
	run = Run
	assert.Equal(t, 2, Main(strings.NewReader(`{"version":2,"pid":1,"nspid":1,"jar_path":"/x"}`), &out))
	assert.Contains(t, out.String(), `"reason":"bad_request"`)
}
