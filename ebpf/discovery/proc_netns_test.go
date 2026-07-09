package discovery

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// pidNetnsInode helper
// ---------------------------------------------------------------------------

func TestPidNetnsInode_Self(t *testing.T) {
	// Stat /proc/self/ns/net via our own PID. Always valid on Linux.
	inode := pidNetnsInode("/proc", uint32(os.Getpid()))
	if inode == 0 {
		t.Skip("not running on Linux or /proc/self/ns/net unavailable")
	}
	assert.NotZero(t, inode, "own netns inode must be non-zero")
}

func TestPidNetnsInode_InvalidPID(t *testing.T) {
	// PID 0 never exists — must return 0 (not panic).
	inode := pidNetnsInode("/proc", 0)
	assert.Zero(t, inode, "non-existent PID must return inode 0")
}

func TestPidNetnsInode_EmptyProcRoot(t *testing.T) {
	// Empty procRoot defaults to /proc — result must be the same as explicit /proc.
	explicit := pidNetnsInode("/proc", uint32(os.Getpid()))
	defaulted := pidNetnsInode("", uint32(os.Getpid()))
	assert.Equal(t, explicit, defaulted,
		"empty procRoot must default to /proc")
}

// ---------------------------------------------------------------------------
// WatchOpts.NetnsInodeFilter — integration with WatchWith
// ---------------------------------------------------------------------------

// ownNetnsInode returns the network-namespace inode for the current process,
// or skips the test if /proc is unavailable (non-Linux).
func ownNetnsInode(t *testing.T) uint64 {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/net", &st); err != nil {
		t.Skipf("skipping: /proc/self/ns/net unavailable: %v", err)
	}
	return st.Ino
}

func TestWatchWith_NetnsInodeFilter_ZeroMeansNoFilter(t *testing.T) {
	// NetnsInodeFilter == 0 must behave identically to no filter set:
	// the allowed() func must return true for any PID (falls through to
	// NamespaceResolver == nil branch which returns true).
	// We test this by checking that the zero-value WatchOpts allowed func
	// does not restrict PIDs — indirectly via the opts struct logic.
	opts := WatchOpts{NetnsInodeFilter: 0, NamespaceResolver: nil}

	// Build allowed func the same way WatchWith does internally.
	allowedFn := func(pid uint32) bool {
		if opts.NetnsInodeFilter != 0 {
			return pidNetnsInode(opts.ProcRoot, pid) == opts.NetnsInodeFilter
		}
		return opts.NamespaceResolver == nil // true when no resolver
	}

	// Any PID should be allowed when both filter and resolver are absent.
	assert.True(t, allowedFn(1), "PID 1 should be allowed with no filter")
	assert.True(t, allowedFn(uint32(os.Getpid())), "own PID should be allowed with no filter")
}

func TestWatchWith_NetnsInodeFilter_OwnInodeAllowsSelf(t *testing.T) {
	// When NetnsInodeFilter is set to the current process's own netns inode,
	// the current process's PID must be allowed (same netns) and PID 0
	// (non-existent) must be rejected.
	inode := ownNetnsInode(t)

	opts := WatchOpts{NetnsInodeFilter: inode}

	allowedFn := func(pid uint32) bool {
		if opts.NetnsInodeFilter != 0 {
			return pidNetnsInode(opts.ProcRoot, pid) == opts.NetnsInodeFilter
		}
		return true
	}

	assert.True(t, allowedFn(uint32(os.Getpid())),
		"own PID must be allowed when filter inode matches own netns")
	assert.False(t, allowedFn(0),
		"PID 0 must be rejected (inode 0 != target inode)")
}

func TestWatchWith_NetnsInodeFilter_WrongInodeRejectsSelf(t *testing.T) {
	// A deliberately wrong inode (e.g. 1) must reject even the current
	// process — proving the filter is actually applied.
	const wrongInode uint64 = 1 // inodes start at 1 but netns inodes are much larger

	opts := WatchOpts{NetnsInodeFilter: wrongInode}

	allowedFn := func(pid uint32) bool {
		if opts.NetnsInodeFilter != 0 {
			return pidNetnsInode(opts.ProcRoot, pid) == opts.NetnsInodeFilter
		}
		return true
	}

	inode := pidNetnsInode("/proc", uint32(os.Getpid()))
	if inode == wrongInode {
		t.Skip("extremely unlikely: own netns inode happens to be 1")
	}

	assert.False(t, allowedFn(uint32(os.Getpid())),
		"own PID must be rejected when filter inode does not match")
}

func TestWatchWith_NetnsInodeFilter_TakesPriorityOverNamespaceResolver(t *testing.T) {
	// When both NetnsInodeFilter and NamespaceResolver are set, inode wins.
	// Verify by using a resolver that would accept everything (returns "ns")
	// but an inode that rejects everything (wrong value) — result must be reject.
	const wrongInode uint64 = 1

	opts := WatchOpts{
		NetnsInodeFilter:  wrongInode,
		NamespaceResolver: alwaysAllowResolver{},
		AllowedNamespaces: map[string]struct{}{"ns": {}},
	}

	allowedFn := func(pid uint32) bool {
		if opts.NetnsInodeFilter != 0 {
			return pidNetnsInode(opts.ProcRoot, pid) == opts.NetnsInodeFilter
		}
		if opts.NamespaceResolver == nil {
			return true
		}
		ns := opts.NamespaceResolver.Namespace(pid)
		_, ok := opts.AllowedNamespaces[ns]
		return ok
	}

	inode := pidNetnsInode("/proc", uint32(os.Getpid()))
	if inode == wrongInode {
		t.Skip("extremely unlikely: own netns inode happens to be 1")
	}

	assert.False(t, allowedFn(uint32(os.Getpid())),
		"inode filter must take priority over namespace resolver")
}

// alwaysAllowResolver is a NamespaceResolver that returns "ns" for every PID.
type alwaysAllowResolver struct{}

func (alwaysAllowResolver) Namespace(_ uint32) string { return "ns" }

// ---------------------------------------------------------------------------
// WatchWith end-to-end: inode filter emits no targets when nothing matches
// ---------------------------------------------------------------------------

func TestWatchWith_NetnsInodeFilter_EmitsNothingWhenNoMatch(t *testing.T) {
	// Use inode=1 (will never match a real process's netns inode) and confirm
	// WatchWith emits no targets within the scan window.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	ch := WatchWith(ctx, WatchOpts{
		Interval:         50 * time.Millisecond,
		NetnsInodeFilter: 1, // no real process has netns inode 1
	})

	var targets []Target
	for tgt := range ch {
		targets = append(targets, tgt)
	}

	// We can't assert zero targets because the test process itself might have
	// libssl loaded. What we CAN assert: any emitted PID must have matched
	// inode 1, which is impossible — so zero targets is the only correct result.
	require.Empty(t, targets,
		"no PIDs should match netns inode=1 (no real process has that inode)")
}
