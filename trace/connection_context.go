package trace

import (
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/OneOfOne/xxhash"
	"github.com/akitasoftware/akita-libs/akinet"
)

const (
	connectionContextMaxEntries  = 100_000
	connectionContextRetention   = 10 * time.Minute
	connectionContextCleanupMask = 1023
)

type unmatchedResponseContext uint8

const (
	unmatchedResponseContextUnknown unmatchedResponseContext = iota
	unmatchedResponseContextResponseFirst
	unmatchedResponseContextRequestSeenLocalCollector
	unmatchedResponseContextRequestSeenOtherCollector
)

type connectionContext struct {
	lastObserved      time.Time
	requestCollectors map[uint64]struct{}
}

// connectionContextTracker retains only hashed connection identities. It is
// shared by the pcap rate-limit collectors in one apidump session, allowing a
// response to distinguish a request seen locally from one seen by another
// collector without exporting connection details to telemetry.
type ConnectionContextTracker struct {
	mu            sync.Mutex
	nextCollector uint64
	observations  uint64
	connections   map[uint64]connectionContext
}

func NewConnectionContextTracker() *ConnectionContextTracker {
	return &ConnectionContextTracker{connections: make(map[uint64]connectionContext)}
}

func (t *ConnectionContextTracker) registerCollector() uint64 {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nextCollector++
	return t.nextCollector
}

func (t *ConnectionContextTracker) observeRequest(pnt akinet.ParsedNetworkTraffic, collectorID uint64) {
	key, ok := connectionContextKey(pnt)
	if !ok || t == nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.prune(time.Now())

	context := t.connections[key]
	if context.requestCollectors == nil {
		context.requestCollectors = make(map[uint64]struct{})
	}
	context.lastObserved = time.Now()
	context.requestCollectors[collectorID] = struct{}{}
	t.connections[key] = context
}

func (t *ConnectionContextTracker) classifyResponse(pnt akinet.ParsedNetworkTraffic, collectorID uint64) unmatchedResponseContext {
	key, ok := connectionContextKey(pnt)
	if !ok || t == nil {
		return unmatchedResponseContextUnknown
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.prune(time.Now())

	context, ok := t.connections[key]
	if !ok || len(context.requestCollectors) == 0 {
		return unmatchedResponseContextResponseFirst
	}
	context.lastObserved = time.Now()
	t.connections[key] = context
	if _, ok := context.requestCollectors[collectorID]; ok {
		return unmatchedResponseContextRequestSeenLocalCollector
	}
	return unmatchedResponseContextRequestSeenOtherCollector
}

func (t *ConnectionContextTracker) prune(now time.Time) {
	t.observations++
	if len(t.connections) < connectionContextMaxEntries && t.observations&connectionContextCleanupMask != 0 {
		return
	}

	threshold := now.Add(-connectionContextRetention)
	for key, context := range t.connections {
		if context.lastObserved.Before(threshold) {
			delete(t.connections, key)
		}
	}
	for len(t.connections) >= connectionContextMaxEntries {
		for key := range t.connections {
			delete(t.connections, key)
			break
		}
	}
}

func connectionContextKey(pnt akinet.ParsedNetworkTraffic) (uint64, bool) {
	if pnt.SrcIP == nil || pnt.DstIP == nil || pnt.SrcPort == 0 || pnt.DstPort == 0 {
		return 0, false
	}

	src := net.JoinHostPort(pnt.SrcIP.String(), strconv.Itoa(pnt.SrcPort))
	dst := net.JoinHostPort(pnt.DstIP.String(), strconv.Itoa(pnt.DstPort))
	if src > dst {
		src, dst = dst, src
	}

	h := xxhash.New64()
	h.WriteString(src)
	h.WriteString(dst)
	return h.Sum64(), true
}
