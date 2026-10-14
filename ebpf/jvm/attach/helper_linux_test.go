// SPDX-License-Identifier: Apache-2.0

//go:build linux

package attach

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// fakeProcDir returns a directory standing in for /proc/<pid>, whose root
// has a /tmp, and that /tmp.
func fakeProcDir(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	tmp := filepath.Join(dir, "root", "tmp")
	require.NoError(t, os.MkdirAll(tmp, 0o1777))
	if _, err := unix.Openat2(unix.AT_FDCWD, tmp, &unix.OpenHow{Flags: unix.O_PATH}); errors.Is(err, unix.ENOSYS) {
		t.Skip("openat2 is not available")
	}
	return dir, tmp
}

// Only the attach that creates the trigger file owns it, signals and removes
// it; another one waits for the listener.
func TestCreateTriggerOwnership(t *testing.T) {
	dir, tmp := fakeProcDir(t)
	trigger := filepath.Join(tmp, ".attach_pid1")

	releaseFirst, owned, err := createTrigger(dir, ".attach_pid1")
	require.NoError(t, err)
	assert.True(t, owned)
	assert.FileExists(t, trigger)

	releaseSecond, owned, err := createTrigger(dir, ".attach_pid1")
	require.NoError(t, err)
	assert.False(t, owned, "a second attach owns the trigger too")
	releaseSecond()
	assert.FileExists(t, trigger, "removed by an attach that does not own it")

	releaseFirst()
	assert.NoFileExists(t, trigger)
}

// A trigger left by an attach that was killed is taken over.
func TestCreateTriggerTakesOverStale(t *testing.T) {
	dir, tmp := fakeProcDir(t)
	trigger := filepath.Join(tmp, ".attach_pid1")
	require.NoError(t, os.WriteFile(trigger, nil, 0o600))
	old := time.Now().Add(-2 * staleTriggerAge)
	require.NoError(t, os.Chtimes(trigger, old, old))

	release, owned, err := createTrigger(dir, ".attach_pid1")
	require.NoError(t, err)
	assert.True(t, owned)
	release()
	assert.NoFileExists(t, trigger)
}
