package rest

import (
	"sync"
	"time"
)

// DefaultIngestRetryAfter is used when the backend omits retry_after_seconds.
const DefaultIngestRetryAfter = 5 * time.Minute

// IngestCooldown tracks keys the backend has refused ingestion for, until the
// backend-provided cooldown elapses. Shared process-wide so DaemonSet per-pod
// apidumps see the same state.
var IngestCooldown = NewIngestCooldownCache()

// IngestCooldownCache maps keys to the earliest time the agent may retry.
type IngestCooldownCache struct {
	mu      sync.Mutex
	entries map[string]time.Time // key -> next_check_at
}

func NewIngestCooldownCache() *IngestCooldownCache {
	return &IngestCooldownCache{
		entries: make(map[string]time.Time),
	}
}

// DiscoveryCooldownKey builds a stable key for a discovered workload.
func DiscoveryCooldownKey(cluster, namespace, workload string) string {
	return cluster + "/" + namespace + "/" + workload
}

// WorkspaceCooldownKey builds a key shared by every pod on the same workspace
// and system env.
func WorkspaceCooldownKey(workspaceID, systemEnv string) string {
	return "workspace/" + workspaceID + "/" + systemEnv
}

// ShouldSkip reports whether key is still within its cooldown.
func (c *IngestCooldownCache) ShouldSkip(key string) bool {
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
func (c *IngestCooldownCache) NextCheckAt(key string) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	next, ok := c.entries[key]
	if !ok || !time.Now().Before(next) {
		return time.Time{}, false
	}
	return next, true
}

// Mark starts a cooldown of retryAfter for key. A non-positive retryAfter
// falls back to DefaultIngestRetryAfter.
func (c *IngestCooldownCache) Mark(key string, retryAfter time.Duration) {
	if retryAfter <= 0 {
		retryAfter = DefaultIngestRetryAfter
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = time.Now().Add(retryAfter)
}

// Clear removes any cooldown for key.
func (c *IngestCooldownCache) Clear(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}
