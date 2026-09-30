package rest

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDiscoveryCacheKey(t *testing.T) {
	assert.Equal(t, "prod/default/api", DiscoveryCacheKey("prod", "default", "api"))
}

func TestDiscoveryTTLCache_MarkAndShouldSkip(t *testing.T) {
	c := NewDiscoveryTTLCache()
	key := DiscoveryCacheKey("c", "ns", "wl")

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

func TestDiscoveryTTLCache_MarkDefaultRetryAfter(t *testing.T) {
	c := NewDiscoveryTTLCache()
	key := "k"
	c.Mark(key, 0)
	next, ok := c.NextCheckAt(key)
	assert.True(t, ok)
	assert.True(t, next.After(time.Now().Add(DefaultDiscoveryTTLRetryAfter-time.Second)))
}

func TestDiscoveryTTLCache_Clear(t *testing.T) {
	c := NewDiscoveryTTLCache()
	key := "k"
	c.Mark(key, time.Hour)
	assert.True(t, c.ShouldSkip(key))
	c.Clear(key)
	assert.False(t, c.ShouldSkip(key))
}
