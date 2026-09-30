package rest

import (
	"sync"
	"time"
)

// DefaultDiscoveryTTLRetryAfter is used when the backend omits
// retry_after_seconds (e.g. older backends that still return 403).
const DefaultDiscoveryTTLRetryAfter = 5 * time.Minute

// DiscoveryTTLCooldown tracks workloads whose discovery traffic TTL has
// expired so the agent can skip /discover until the backend-provided cooldown
// elapses. Shared process-wide so DaemonSet per-pod apidumps see the same state.
var DiscoveryTTLCooldown = NewDiscoveryTTLCache()

// DiscoveryTTLCache maps discovery workload keys to the earliest time the
// agent may call /discover again.
type DiscoveryTTLCache struct {
	mu      sync.Mutex
	entries map[string]time.Time // key -> next_check_at
}

func NewDiscoveryTTLCache() *DiscoveryTTLCache {
	return &DiscoveryTTLCache{
		entries: make(map[string]time.Time),
	}
}

// DiscoveryCacheKey builds a stable key for a discovered workload.
func DiscoveryCacheKey(cluster, namespace, workload string) string {
	return cluster + "/" + namespace + "/" + workload
}

// ShouldSkip reports whether /discover should be skipped for key because a
// prior TTL-expiry response is still within its retry_after cooldown.
func (c *DiscoveryTTLCache) ShouldSkip(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	next, ok := c.entries[key]
	if !ok {
		return false
	}
	if time.Now().Before(next) {
		return true
	}
	delete(c.entries, key)
	return false
}

// NextCheckAt returns the scheduled recheck time for key, if any.
func (c *DiscoveryTTLCache) NextCheckAt(key string) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	next, ok := c.entries[key]
	if !ok || !time.Now().Before(next) {
		return time.Time{}, false
	}
	return next, true
}

// Mark records that key should not call /discover again until retryAfter
// elapses. A non-positive retryAfter falls back to DefaultDiscoveryTTLRetryAfter.
func (c *DiscoveryTTLCache) Mark(key string, retryAfter time.Duration) {
	if retryAfter <= 0 {
		retryAfter = DefaultDiscoveryTTLRetryAfter
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = time.Now().Add(retryAfter)
}

// Clear removes any cooldown for key (e.g. after a successful discover).
func (c *DiscoveryTTLCache) Clear(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}
