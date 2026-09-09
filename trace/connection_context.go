package trace

import (
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/OneOfOne/xxhash"
	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/google/uuid"
	"github.com/postmanlabs/postman-insights-agent/capturestats"
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

	// The response carried no usable connection identity (a nil address or a
	// zero port), so the tracker was never consulted. Distinct from Unknown:
	// this is a property of the message we were handed, not an unclassifiable
	// lookup result, and lumping the two together makes Unknown mean "either
	// we could not build a key or the classifier returned something we do not
	// recognize" -- two different bugs to chase.
	unmatchedResponseContextKeyInvalid

	// No tracker was wired into this collector, so no context exists to
	// consult for any response it drops (currently the eBPF chain -- see
	// apidump.Run). Also distinct from Unknown: it says the classification
	// was never attempted, rather than attempted and inconclusive.
	unmatchedResponseContextTrackerUnavailable
)

// pairExpiryContext reports what the agent knew about the missing half of a
// witness that expired unpaired. It answers the question the direction-only
// witness_pair_expired_* counters cannot: the response side of the funnel now
// reports that a request was seen on a response's own stream
// (request_seen_same_stream), and this is the same claim viewed from the other
// end.
type pairExpiryContext uint8

const (
	pairExpiryContextUnknown pairExpiryContext = iota

	// A message on this witness's TCP stream reached the rate-limit collector
	// and was discarded as unmatched. Stream-level, not message-level: a
	// keep-alive stream carries many exchanges, so this does not prove the
	// rejected message was this witness's own companion.
	pairExpiryContextPeerRejected

	// No message on this stream was ever discarded as unmatched, so nothing
	// contradicts "the companion simply never arrived". Note a stream lost to
	// pruning or capacity eviction also lands here -- read it against
	// stats.UnmatchedResponseStreamPruned and
	// stats.UnmatchedResponseStreamCapacityEvicted.
	pairExpiryContextPeerNeverObserved

	// The witness carried no stream identity, so no lookup was possible.
	// Should not occur for HTTP traffic; a nonzero count means a producer
	// stopped populating it.
	pairExpiryContextPeerStreamUnknown

	// No tracker was wired into this collector, so the question cannot be
	// asked at all (currently the eBPF chain -- see apidump.Run).
	pairExpiryContextPeerTrackerUnavailable
)

type connectionContext struct {
	lastObserved      time.Time
	requestCollectors map[uint64]struct{}
}

// ConnectionContextTracker retains only hashed identities -- never addresses,
// ports or stream UUIDs -- so nothing here can leak connection details into
// telemetry. It is shared by one apidump session's pcap collectors and holds
// two indexes at two granularities:
//
//   - connections, keyed by a direction-normalized address pair, lets an
//     unmatched response distinguish a request seen locally from one seen by
//     another collector.
//   - unmatchedResponseStreams, keyed by TCP stream, lets a witness expiring
//     unpaired ask whether a message on its own stream was already discarded
//     as unmatched.
//
// The second is keyed by stream rather than address pair on purpose: an
// address pair can be reused by a later connection (see the ordering comment
// in rateLimitCollector.recordUnmatchedResponse), a stream cannot, and keying
// it this way puts it in the same key space as
// rateLimitCollector.SeenRequestStreams so the two sides are directly
// comparable.
type ConnectionContextTracker struct {
	mu            sync.Mutex
	nextCollector uint64
	observations  uint64
	connections   map[uint64]connectionContext

	// Streams on which a message was discarded as unmatched, and when it last
	// happened. Bounded by the same retention and cap as connections.
	unmatchedResponseStreams map[uint64]time.Time

	// Where the tracker's own health counters go. Held here rather than
	// passed per call because pruning is triggered from inside observeRequest
	// and classifyResponse, which have no reason to know about stats
	// otherwise. One tracker is created per apidump session and is shared
	// only by that session's pcap collectors (the eBPF chain passes nil), so
	// this is the same per-session Stats those collectors report to.
	stats *capturestats.Stats
}

func NewConnectionContextTracker(stats *capturestats.Stats) *ConnectionContextTracker {
	return &ConnectionContextTracker{
		connections:              make(map[uint64]connectionContext),
		unmatchedResponseStreams: make(map[uint64]time.Time),
		stats:                    stats,
	}
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
	if t == nil {
		return
	}
	key, ok := connectionContextKey(pnt)
	if !ok {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.prune(time.Now())

	context, existing := t.connections[key]
	if !existing {
		// Only a new key grows the map, so only then is room needed.
		t.stats.AddConnectionContextCapacityEvicted(
			evictOneForInsert(t.connections, connectionContextMaxEntries))
	}
	if context.requestCollectors == nil {
		context.requestCollectors = make(map[uint64]struct{})
	}
	context.lastObserved = time.Now()
	context.requestCollectors[collectorID] = struct{}{}
	t.connections[key] = context
	t.recordOccupancy()
}

// classifyResponse reports what the tracker knows about the connection an
// unmatched response arrived on.
//
// A ResponseFirst result means only that this tracker holds no request for
// the connection *now*. That is not the same as never having seen one: prune
// discards entries by age and, at the entry cap, arbitrarily. Read it
// alongside stats.ConnectionContextPruned and
// stats.ConnectionContextCapacityEvicted, which count exactly those two
// erasures.
func (t *ConnectionContextTracker) classifyResponse(pnt akinet.ParsedNetworkTraffic, collectorID uint64) unmatchedResponseContext {
	if t == nil {
		return unmatchedResponseContextTrackerUnavailable
	}
	key, ok := connectionContextKey(pnt)
	if !ok {
		return unmatchedResponseContextKeyInvalid
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

// observeUnmatchedResponse records that a message on this stream was discarded
// as unmatched, whatever subreason the drop was attributed to. Every unmatched
// response is evidence of a key-matching failure on its stream, including the
// ones an exact tombstone already explained: those were still messages the
// agent captured and then threw away before a witness could be paired.
func (t *ConnectionContextTracker) observeUnmatchedResponse(streamID uuid.UUID) {
	if t == nil {
		return
	}
	key, ok := streamContextKey(streamID)
	if !ok {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.prune(time.Now())

	if _, existing := t.unmatchedResponseStreams[key]; !existing {
		t.stats.AddUnmatchedResponseStreamCapacityEvicted(
			evictOneForInsert(t.unmatchedResponseStreams, connectionContextMaxEntries))
	}
	t.unmatchedResponseStreams[key] = time.Now()
}

// classifyPairExpiries answers, for each stream key, whether a message on that
// stream was discarded as unmatched. Results are returned positionally.
//
// Batched rather than one call per witness for two reasons. A single pair-cache
// sweep can expire thousands of witnesses (6,381 in one observed run), and this
// mutex is shared with the live capture path, so per-witness acquisition would
// contend hardest during exactly the loss episodes these counters describe.
// And it lets the caller classify after releasing each witness's own lock,
// keeping the two mutexes from ever being held at once.
//
// A zero key means the caller could not derive a stream identity; it is
// reported as PeerStreamUnknown rather than being looked up.
func (t *ConnectionContextTracker) classifyPairExpiries(streamKeys []uint64) []pairExpiryContext {
	out := make([]pairExpiryContext, len(streamKeys))
	if t == nil {
		for i := range out {
			out[i] = pairExpiryContextPeerTrackerUnavailable
		}
		return out
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	for i, key := range streamKeys {
		switch {
		case key == 0:
			out[i] = pairExpiryContextPeerStreamUnknown
		default:
			if _, ok := t.unmatchedResponseStreams[key]; ok {
				out[i] = pairExpiryContextPeerRejected
			} else {
				out[i] = pairExpiryContextPeerNeverObserved
			}
		}
	}
	return out
}

// prune drops entries that have aged out of either index, and counts what it
// dropped. Pruning erases the evidence classifyResponse and
// classifyPairExpiries depend on, so an uncounted prune shows up later as a
// ResponseFirst or PeerNeverObserved that cannot be challenged.
//
// Sampled, not run on every observation: the sweep is O(entries), so gating it
// on the cleanup mask amortizes the per-message cost to O(1). It deliberately
// does *not* force a sweep when an index is full -- capacity is enforced at
// insertion by evictOneForInsert, so neither index can exceed its cap, and
// force-sweeping at saturation would turn every single message into a full
// scan of both maps on the capture goroutine. That is the opposite of what a
// bounded index is for: stalling Process backs up the parsedChan drain into
// libpcap's buffer and shows up as pcap_packets_dropped.
//
// Callers must hold t.mu.
func (t *ConnectionContextTracker) prune(now time.Time) {
	t.observations++
	if t.observations&connectionContextCleanupMask != 0 {
		return
	}

	var pruned, streamsPruned uint64

	threshold := now.Add(-connectionContextRetention)
	for key, context := range t.connections {
		if context.lastObserved.Before(threshold) {
			delete(t.connections, key)
			pruned++
		}
	}
	for key, lastObserved := range t.unmatchedResponseStreams {
		if lastObserved.Before(threshold) {
			delete(t.unmatchedResponseStreams, key)
			streamsPruned++
		}
	}

	t.stats.AddConnectionContextPruned(pruned)
	t.stats.AddUnmatchedResponseStreamPruned(streamsPruned)
	t.recordOccupancy()
}

// evictOneForInsert makes room for one new entry, deleting an arbitrary
// existing one if the map is already at its cap. Returns how many it evicted,
// so the caller can count it.
//
// O(1): it deletes whichever key the map iterator yields first, which is why
// the eviction has to be reported. An evicted connection turns a later
// ResponseFirst into a claim the tracker can no longer support, so a nonzero
// eviction count means that reason is unreliable for the interval rather than
// merely stale.
//
// Enforced here rather than in prune so that read paths -- classifyResponse,
// classifyPairExpiries -- never destroy evidence they were only asked to
// consult.
func evictOneForInsert[K comparable, V any](m map[K]V, maxEntries int) uint64 {
	if len(m) < maxEntries {
		return 0
	}
	for key := range m {
		delete(m, key)
		return 1
	}
	return 0
}

// recordOccupancy publishes the tracker's current size. Called on every path
// that changes it, so the gauge does not go stale between the sampled prune
// runs. Callers must hold t.mu.
func (t *ConnectionContextTracker) recordOccupancy() {
	t.stats.AddConnectionContextOccupancy(uint64(len(t.connections)))
}

// streamContextKey hashes a TCP stream identity. Returns false for the zero
// UUID, which is what a producer that does not set a stream ID leaves behind.
func streamContextKey(streamID uuid.UUID) (uint64, bool) {
	if streamID == uuid.Nil {
		return 0, false
	}
	h := xxhash.New64()
	h.WriteString(streamID.String())
	return h.Sum64(), true
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
