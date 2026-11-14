package jvm

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKindFromMaps(t *testing.T) {
	for _, tc := range []struct {
		name string
		maps string
		want Kind
	}{
		{"hotspot", "7f00-7f01 r-xp 00000000 fd:00 12 /opt/java/openjdk/lib/server/libjvm.so\n", HotSpot},
		{"hotspot, trailing space", "7f00-7f01 r-xp 00000000 fd:00 12 /usr/lib/jvm/lib/server/libjvm.so  \n", HotSpot},
		// OpenJ9 maps a libjvm.so redirector as well as libj9vm.
		{"openj9", "7f00-7f01 r-xp 0 fd:00 1 /opt/java/lib/default/libjvm.so\n7f02-7f03 r-xp 0 fd:00 2 /opt/java/lib/default/libj9vm29.so\n", OpenJ9},
		{"not a jvm", "7f00-7f01 r-xp 0 fd:00 1 /usr/lib/libssl.so.3\n", 0},
		{"lookalike", "7f00-7f01 r-xp 0 fd:00 1 /usr/lib/libjvm.so.bak\n7f02-7f03 r-xp 0 fd:00 2 /tmp/notlibjvm.so\n", 0},
		{"empty", "", 0},
	} {
		assert.Equal(t, tc.want, KindFromMaps([]byte(tc.maps)), tc.name)
	}
}

func TestParseStartTime(t *testing.T) {
	// The command may contain spaces and parentheses.
	stat := "4242 (java (main) x) S 1 4242 4242 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 30 0 987654 123 456\n"
	got, err := parseStartTime([]byte(stat))
	require.NoError(t, err)
	assert.Equal(t, uint64(987654), got)

	_, err = parseStartTime([]byte("4242 (java) S 1 2"))
	assert.Error(t, err)
	_, err = parseStartTime([]byte("garbage"))
	assert.Error(t, err)
}

func TestParseStatus(t *testing.T) {
	var p Process
	status := "Name:\tjava\nUid:\t1000\t1001\t1001\t1001\nGid:\t2000\t2001\t2001\t2001\nNSpid:\t31337\t7\n"
	require.NoError(t, parseStatus([]byte(status), &p))
	assert.Equal(t, uint32(7), p.NSPID, "the PID in the JVM's own namespace")
	assert.Equal(t, uint32(1001), p.UID, "the effective uid")
	assert.Equal(t, uint32(2001), p.GID, "the effective gid")

	assert.Error(t, parseStatus([]byte("Name:\tjava\nUid:\t1000\t1000\t1000\t1000\n"), &p))
}

// fakeProc writes a /proc/<pid> entry with the given maps under root.
func fakeProc(t *testing.T, root string, pid uint32, startTime uint64, maps string) {
	t.Helper()
	dir := filepath.Join(root, strconv.FormatUint(uint64(pid), 10))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "ns"), 0o755))
	files := map[string]string{
		"maps":   maps,
		"stat":   strconv.FormatUint(uint64(pid), 10) + " (java) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 30 0 " + strconv.FormatUint(startTime, 10) + " 0 0\n",
		"status": "Name:\tjava\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nNSpid:\t" + strconv.FormatUint(uint64(pid), 10) + "\t1\n",
		"ns/mnt": "",
	}
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
	}
}

func TestInspect(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 100, 5555, "7f00-7f01 r-xp 0 fd:00 1 /opt/java/lib/server/libjvm.so\n")
	fakeProc(t, root, 101, 6666, "7f00-7f01 r-xp 0 fd:00 1 /usr/bin/python3\n")

	p, err := Inspect(root, 100, nil)
	require.NoError(t, err)
	assert.Equal(t, root, p.ProcRoot)
	assert.Equal(t, Key{100, 5555}, p.Key())
	assert.Equal(t, HotSpot, p.Kind)
	assert.Equal(t, uint32(1), p.NSPID)
	assert.Equal(t, uint32(1000), p.UID)
	assert.NotZero(t, p.MountNS)
	assert.True(t, Alive(p))

	_, err = Inspect(root, 101, nil)
	assert.True(t, errors.Is(err, ErrNotJVM), "%v", err)
	_, err = Inspect(root, 102, nil)
	assert.Error(t, err, "no such process")

	// A different process now has the PID.
	fakeProc(t, root, 100, 7777, "")
	assert.False(t, Alive(p))
}
