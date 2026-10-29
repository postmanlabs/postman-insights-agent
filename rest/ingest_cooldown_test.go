package rest

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDiscoveryCooldownKey(t *testing.T) {
	assert.Equal(t, "discover:prod/default/api", DiscoveryCooldownKey("prod", "default", "api"))
}

func TestCooldownKeys_DiscoveryAndWorkspaceNeverCollide(t *testing.T) {
	assert.NotEqual(t, WorkspaceCooldownKey("ws-1", "env-1"), DiscoveryCooldownKey("workspace", "ws-1", "env-1"))
}

func TestIngestCooldownCache_MarkAndShouldSkip(t *testing.T) {
	c := NewIngestCooldownCache()
	key := DiscoveryCooldownKey("c", "ns", "wl")

	assert.False(t, c.ShouldSkip(key))

	c.Mark(key, 50*time.Millisecond)
	assert.True(t, c.ShouldSkip(key))

	next, ok := c.NextCheckAt(key)
	assert.True(t, ok)
	assert.True(t, next.After(time.Now()))

	time.Sleep(60 * time.Millisecond)
	assert.False(t, c.ShouldSkip(key))
	_, ok = c.NextCheckAt(key)
	assert.False(t, ok)
}

func TestIngestCooldownCache_MarkDefaultRetryAfter(t *testing.T) {
	c := NewIngestCooldownCache()
	key := "k"
	c.Mark(key, 0)
	next, ok := c.NextCheckAt(key)
	assert.True(t, ok)
	assert.True(t, next.After(time.Now().Add(DefaultIngestRetryAfter-time.Second)))
}

func TestIngestCooldownCache_Clear(t *testing.T) {
	c := NewIngestCooldownCache()
	key := "k"
	c.Mark(key, time.Hour)
	assert.True(t, c.ShouldSkip(key))
	c.Clear(key)
	assert.False(t, c.ShouldSkip(key))
}

func TestIngestCooldownCache_MarkedWorkspace_SkipsOnlySameWorkspaceAndEnv(t *testing.T) {
	c := NewIngestCooldownCache()
	key := WorkspaceCooldownKey("ws-1", "env-1")
	c.Mark(key, time.Hour)

	assert.True(t, c.ShouldSkip(key))
	assert.False(t, c.ShouldSkip(WorkspaceCooldownKey("ws-1", "env-2")))
	assert.False(t, c.ShouldSkip(WorkspaceCooldownKey("ws-2", "env-1")))

	c.Clear(key)
	assert.False(t, c.ShouldSkip(key))
}
