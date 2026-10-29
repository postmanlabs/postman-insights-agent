package discovery

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/postmanlabs/postman-insights-agent/ebpf/jvm"
)

// writeFakeProc writes a /proc/<pid> entry under root: a process started at
// startTime with the given maps.
func writeFakeProc(t *testing.T, root string, pid uint32, startTime uint64, maps string) {
	t.Helper()
	dir := filepath.Join(root, strconv.FormatUint(uint64(pid), 10))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "ns"), 0o755))
	p := strconv.FormatUint(uint64(pid), 10)
	files := map[string]string{
		"maps":   maps,
		"stat":   p + " (java) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 30 0 " + strconv.FormatUint(startTime, 10) + " 0 0\n",
		"status": "Name:\tjava\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nNSpid:\t" + p + "\t1\n",
		"ns/mnt": "",
		"ns/net": "",
	}
	for name, content := range files {
		writeAtomic(t, filepath.Join(dir, name), content)
	}
}

// writeAtomic replaces a fake /proc file in one step, as the kernel does: a
// scan running meanwhile must not read it empty.
func writeAtomic(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path+".tmp", []byte(content), 0o644))
	require.NoError(t, os.Rename(path+".tmp", path))
}

const libjvmMaps = "7f00-7f01 r-xp 00000000 fd:00 1 /opt/java/openjdk/lib/server/libjvm.so\n"

func next(t *testing.T, ch <-chan Target) Target {
	t.Helper()
	select {
	case tgt := <-ch:
		return tgt
	case <-time.After(5 * time.Second):
		t.Fatal("no discovery event")
	}
	return Target{}
}

func TestWatchEmitsJVMs(t *testing.T) {
	root := t.TempDir()
	writeFakeProc(t, root, 4242, 1000, libjvmMaps)
	writeFakeProc(t, root, 4343, 1000, "7f00-7f01 r-xp 0 fd:00 1 /usr/bin/python3\n")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := WatchWith(ctx, WatchOpts{Interval: 20 * time.Millisecond, ProcRoot: root, JVMs: true})

	tgt := next(t, ch)
	assert.Equal(t, uint32(4242), tgt.PID)
	assert.Equal(t, uint64(1000), tgt.StartTime)
	assert.False(t, tgt.Removed)
	assert.Nil(t, tgt.Lib, "the JVM does not use libssl")
	require.NotNil(t, tgt.JVM)
	assert.Equal(t, jvm.HotSpot, tgt.JVM.Kind)
	assert.Equal(t, jvm.Key{PID: 4242, StartTime: 1000}, tgt.JVM.Key())

	// Without JVMs, the same process is not a target.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()
	for tgt := range WatchWith(ctx2, WatchOpts{Interval: 20 * time.Millisecond, ProcRoot: root}) {
		t.Errorf("unexpected target %+v", tgt)
	}
}

// A PID reused by a new process is reported as the old one leaving and the new
// one arriving, so state kept for the old process is never applied to the new.
func TestWatchPIDReuse(t *testing.T) {
	root := t.TempDir()
	writeFakeProc(t, root, 4242, 1000, libjvmMaps)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := WatchWith(ctx, WatchOpts{Interval: 20 * time.Millisecond, ProcRoot: root, JVMs: true})
	first := next(t, ch)
	require.Equal(t, uint64(1000), first.StartTime)

	writeFakeProc(t, root, 4242, 2000, libjvmMaps)
	gone := next(t, ch)
	assert.True(t, gone.Removed)
	assert.Equal(t, uint32(4242), gone.PID)
	assert.Equal(t, uint64(1000), gone.StartTime)
	again := next(t, ch)
	assert.False(t, again.Removed)
	require.NotNil(t, again.JVM)
	assert.Equal(t, uint64(2000), again.JVM.StartTime)

	require.NoError(t, os.RemoveAll(filepath.Join(root, "4242")))
	gone = next(t, ch)
	assert.True(t, gone.Removed)
	assert.Equal(t, uint64(2000), gone.StartTime)
}

// A JVM that loads libssl after it was first seen is emitted again, with
// libssl, so its uprobes get attached; a scan that misses the mapping once
// emits nothing.
func TestWatchEmitsLibSSLLoadedLater(t *testing.T) {
	root := t.TempDir()
	writeFakeProc(t, root, 4242, 1000, libjvmMaps)
	lib := filepath.Join(root, "4242", "root", "usr", "lib", "libssl.so.3")
	require.NoError(t, os.MkdirAll(filepath.Dir(lib), 0o755))
	require.NoError(t, os.WriteFile(lib, nil, 0o644))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := WatchWith(ctx, WatchOpts{Interval: 20 * time.Millisecond, ProcRoot: root, JVMs: true})
	first := next(t, ch)
	require.NotNil(t, first.JVM)
	require.Nil(t, first.Lib)

	withSSL := libjvmMaps + "7f02-7f03 r-xp 00000000 fd:00 2 /usr/lib/libssl.so.3\n"
	writeAtomic(t, filepath.Join(root, "4242", "maps"), withSSL)
	update := next(t, ch)
	assert.False(t, update.Removed)
	assert.Equal(t, uint32(4242), update.PID)
	assert.Equal(t, uint64(1000), update.StartTime)
	require.NotNil(t, update.Lib)
	assert.NotNil(t, update.JVM)

	// Missing once, then back: no events.
	writeAtomic(t, filepath.Join(root, "4242", "maps"), libjvmMaps)
	time.Sleep(100 * time.Millisecond)
	writeAtomic(t, filepath.Join(root, "4242", "maps"), withSSL)
	select {
	case tgt := <-ch:
		t.Fatalf("unexpected event %+v", tgt)
	case <-time.After(200 * time.Millisecond):
	}
}

// The netns filter is applied before a process's maps are read.
func TestWatchNetnsFilterSkipsOtherPods(t *testing.T) {
	root := t.TempDir()
	writeFakeProc(t, root, 4242, 1000, libjvmMaps)
	st := statIno(t, filepath.Join(root, "4242", "ns", "net"))

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	for tgt := range WatchWith(ctx, WatchOpts{Interval: 20 * time.Millisecond, ProcRoot: root, JVMs: true, NetnsInodeFilter: st + 1}) {
		t.Errorf("target from another netns: %+v", tgt)
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	tgt := next(t, WatchWith(ctx2, WatchOpts{Interval: 20 * time.Millisecond, ProcRoot: root, JVMs: true, NetnsInodeFilter: st}))
	assert.Equal(t, uint32(4242), tgt.PID)
}

func statIno(t *testing.T, path string) uint64 {
	t.Helper()
	var st syscall.Stat_t
	require.NoError(t, syscall.Stat(path, &st))
	return st.Ino
}
