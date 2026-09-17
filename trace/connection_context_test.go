package trace

import (
	"net"
	"testing"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/google/uuid"
	"github.com/postmanlabs/postman-insights-agent/capturestats"
)

func TestConnectionContextTrackerClassifiesRequestOwnership(t *testing.T) {
	tracker := NewConnectionContextTracker(capturestats.New())
	firstCollector := tracker.registerCollector()
	secondCollector := tracker.registerCollector()
	request := connectionContextTraffic(net.IPv4(10, 0, 0, 1), 8080, net.IPv4(10, 0, 0, 2), 50000)
	response := connectionContextTraffic(net.IPv4(10, 0, 0, 2), 50000, net.IPv4(10, 0, 0, 1), 8080)

	tracker.observeRequest(request, firstCollector)
	if got := tracker.classifyResponse(response, firstCollector); got != unmatchedResponseContextRequestSeenLocalCollector {
		t.Fatalf("local response context = %d, want local collector", got)
	}
	if got := tracker.classifyResponse(response, secondCollector); got != unmatchedResponseContextRequestSeenOtherCollector {
		t.Fatalf("other response context = %d, want other collector", got)
	}
	if got := tracker.classifyResponse(connectionContextTraffic(net.IPv4(10, 0, 0, 3), 50001, net.IPv4(10, 0, 0, 1), 8080), firstCollector); got != unmatchedResponseContextResponseFirst {
		t.Fatalf("unseen response context = %d, want response first", got)
	}
	if got := tracker.classifyResponse(akinet.ParsedNetworkTraffic{}, firstCollector); got != unmatchedResponseContextKeyInvalid {
		t.Fatalf("incomplete response context = %d, want key invalid", got)
	}
	var absent *ConnectionContextTracker
	if got := absent.classifyResponse(response, firstCollector); got != unmatchedResponseContextTrackerUnavailable {
		t.Fatalf("nil tracker response context = %d, want tracker unavailable", got)
	}
}

func connectionContextTraffic(src net.IP, srcPort int, dst net.IP, dstPort int) akinet.ParsedNetworkTraffic {
	return akinet.ParsedNetworkTraffic{SrcIP: src, SrcPort: srcPort, DstIP: dst, DstPort: dstPort}
}

// prune's two erasure paths must be counted separately: age-based attrition
// is expected, while capacity eviction deletes whichever keys the map
// iterator yields and therefore invalidates response_first counts from the
// same interval.
func TestConnectionContextTrackerCountsAgePruning(t *testing.T) {
	stats := capturestats.New()
	tracker := NewConnectionContextTracker(stats)
	collector := tracker.registerCollector()

	fresh := connectionContextTraffic(net.IPv4(10, 0, 0, 1), 8080, net.IPv4(10, 0, 0, 2), 50000)
	tracker.observeRequest(fresh, collector)
	staleKey, _ := connectionContextKey(connectionContextTraffic(net.IPv4(10, 0, 0, 1), 8080, net.IPv4(10, 0, 0, 3), 50001))
	tracker.connections[staleKey] = connectionContext{
		lastObserved:      time.Now().Add(-2 * connectionContextRetention),
		requestCollectors: map[uint64]struct{}{collector: {}},
	}
	// Inserted straight into the map, so publish the occupancy the way the
	// observe/classify paths do.
	tracker.recordOccupancy()

	if got := stats.Snapshot().ConnectionContextEntriesPeak; got != 2 {
		t.Fatalf("peak occupancy before pruning = %d, want 2", got)
	}

	// prune only does work on a sampled observation; select one directly
	// rather than driving 1024 messages through the tracker.
	tracker.observations = connectionContextCleanupMask
	tracker.prune(time.Now())

	snapshot := stats.Snapshot()
	if snapshot.ConnectionContextPruned != 1 {
		t.Fatalf("age-pruned entries = %d, want 1", snapshot.ConnectionContextPruned)
	}
	if snapshot.ConnectionContextCapacityEvicted != 0 {
		t.Fatalf("capacity evictions = %d, want 0", snapshot.ConnectionContextCapacityEvicted)
	}
	if snapshot.ConnectionContextEntries != 1 {
		t.Fatalf("entries after pruning = %d, want 1", snapshot.ConnectionContextEntries)
	}
	// The peak is a running maximum, so pruning must not lower it: the
	// telemetry path ships its delta and would otherwise underflow to zero.
	if snapshot.ConnectionContextEntriesPeak != 2 {
		t.Fatalf("peak occupancy = %d, want 2", snapshot.ConnectionContextEntriesPeak)
	}

	// The pruned connection's request is now unknown to the tracker, which is
	// exactly the response_first that ConnectionContextPruned qualifies.
	stale := connectionContextTraffic(net.IPv4(10, 0, 0, 3), 50001, net.IPv4(10, 0, 0, 1), 8080)
	if got := tracker.classifyResponse(stale, collector); got != unmatchedResponseContextResponseFirst {
		t.Fatalf("pruned connection response context = %d, want response first", got)
	}
}

// Capacity is enforced when a new key is inserted, not by prune, and costs
// O(1) -- it deletes whichever key the map iterator yields first.
func TestConnectionContextTrackerEvictsAtCapacityOnInsert(t *testing.T) {
	stats := capturestats.New()
	tracker := NewConnectionContextTracker(stats)
	collector := tracker.registerCollector()

	now := time.Now()
	for i := range uint64(connectionContextMaxEntries) {
		tracker.connections[i] = connectionContext{lastObserved: now}
	}

	fresh := connectionContextTraffic(net.IPv4(10, 0, 0, 1), 8080, net.IPv4(10, 0, 0, 2), 50000)
	tracker.observeRequest(fresh, collector)

	if got := len(tracker.connections); got != connectionContextMaxEntries {
		t.Fatalf("entries after insert at cap = %d, want %d", got, connectionContextMaxEntries)
	}
	snapshot := stats.Snapshot()
	if snapshot.ConnectionContextCapacityEvicted != 1 {
		t.Fatalf("capacity evictions = %d, want 1", snapshot.ConnectionContextCapacityEvicted)
	}

	// Re-observing an existing connection does not grow the map, so it must
	// not evict anything either.
	tracker.observeRequest(fresh, collector)
	if got := stats.Snapshot().ConnectionContextCapacityEvicted; got != 1 {
		t.Fatalf("capacity evictions after re-observing = %d, want 1", got)
	}
}

// A saturated tracker must not sweep on every observation. The guard used to
// short-circuit the cleanup mask whenever an index was full, which made every
// message scan both maps end to end -- O(entries) per message on the capture
// goroutine, where stalling Process backs up into libpcap and surfaces as
// dropped packets.
func TestConnectionContextTrackerDoesNotSweepPerObservationAtCapacity(t *testing.T) {
	stats := capturestats.New()
	tracker := NewConnectionContextTracker(stats)
	collector := tracker.registerCollector()

	// Every entry is old enough to be swept, so any sweep is visible in the
	// age-pruned counter.
	stale := time.Now().Add(-2 * connectionContextRetention)
	for i := range uint64(connectionContextMaxEntries) {
		tracker.connections[i] = connectionContext{lastObserved: stale}
	}

	// Well under the cleanup mask, so none of these should trigger a sweep.
	const observations = 10
	for i := 0; i < observations; i++ {
		tracker.observeRequest(
			connectionContextTraffic(net.IPv4(10, 0, 0, 1), 8080+i, net.IPv4(10, 0, 0, 2), 50000), collector)
	}

	snapshot := stats.Snapshot()
	if snapshot.ConnectionContextPruned != 0 {
		t.Fatalf("age-pruned %d entries without reaching a sampled observation; the sweep is not mask-gated",
			snapshot.ConnectionContextPruned)
	}
	if snapshot.ConnectionContextCapacityEvicted != observations {
		t.Fatalf("capacity evictions = %d, want %d (one O(1) eviction per new key)",
			snapshot.ConnectionContextCapacityEvicted, observations)
	}
	if got := len(tracker.connections); got != connectionContextMaxEntries {
		t.Fatalf("entries = %d, want the map pinned at %d", got, connectionContextMaxEntries)
	}
}

// The stream index is what lets a witness expiring unpaired discover that its
// companion was captured and then discarded. It must be keyed by stream, and
// it must be populated for every unmatched response regardless of which
// subreason the drop was attributed to.
func TestConnectionContextTrackerClassifiesPairExpiries(t *testing.T) {
	stats := capturestats.New()
	tracker := NewConnectionContextTracker(stats)

	rejected := uuid.New()
	quiet := uuid.New()
	tracker.observeUnmatchedResponse(rejected)

	rejectedKey, ok := streamContextKey(rejected)
	if !ok {
		t.Fatal("expected a usable stream key")
	}
	quietKey, _ := streamContextKey(quiet)

	got := tracker.classifyPairExpiries([]uint64{rejectedKey, quietKey, 0})
	want := []pairExpiryContext{
		pairExpiryContextPeerRejected,
		pairExpiryContextPeerNeverObserved,
		pairExpiryContextPeerStreamUnknown,
	}
	if len(got) != len(want) {
		t.Fatalf("classified %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d classified as %d, want %d", i, got[i], want[i])
		}
	}

	// The zero UUID must not silently register a stream.
	tracker.observeUnmatchedResponse(uuid.Nil)
	if len(tracker.unmatchedResponseStreams) != 1 {
		t.Fatalf("stream index holds %d entries, want 1", len(tracker.unmatchedResponseStreams))
	}
}

// A nil tracker must report that the question could not be asked, rather than
// answering "the companion was never observed" -- the eBPF chain wires no
// tracker, and a false negative there would look like real evidence.
func TestConnectionContextTrackerNilClassifiesUnavailable(t *testing.T) {
	var absent *ConnectionContextTracker

	got := absent.classifyPairExpiries([]uint64{1, 2})
	if len(got) != 2 {
		t.Fatalf("classified %d entries, want 2", len(got))
	}
	for i, reason := range got {
		if reason != pairExpiryContextPeerTrackerUnavailable {
			t.Fatalf("entry %d classified as %d, want tracker unavailable", i, reason)
		}
	}

	// Must not panic.
	absent.observeUnmatchedResponse(uuid.New())
}

// Stream-index attrition is counted under its own names. Folding it into
// connection_context_pruned would merge two different populations -- and a
// stream lost here is what turns a peer_rejected into a peer_never_observed.
func TestConnectionContextTrackerCountsStreamIndexPruning(t *testing.T) {
	stats := capturestats.New()
	tracker := NewConnectionContextTracker(stats)

	fresh := uuid.New()
	tracker.observeUnmatchedResponse(fresh)
	staleKey, _ := streamContextKey(uuid.New())
	tracker.unmatchedResponseStreams[staleKey] = time.Now().Add(-2 * connectionContextRetention)

	tracker.observations = connectionContextCleanupMask
	tracker.prune(time.Now())

	snapshot := stats.Snapshot()
	if snapshot.UnmatchedResponseStreamPruned != 1 {
		t.Fatalf("stream-index age-pruned = %d, want 1", snapshot.UnmatchedResponseStreamPruned)
	}
	if snapshot.UnmatchedResponseStreamCapacityEvicted != 0 {
		t.Fatalf("stream-index capacity evictions = %d, want 0", snapshot.UnmatchedResponseStreamCapacityEvicted)
	}
	// The connection map was untouched, so its counters must stay clean.
	if snapshot.ConnectionContextPruned != 0 {
		t.Fatalf("connection pruned = %d, want 0 (populations must not be merged)", snapshot.ConnectionContextPruned)
	}

	freshKey, _ := streamContextKey(fresh)
	if got := tracker.classifyPairExpiries([]uint64{freshKey, staleKey}); got[0] != pairExpiryContextPeerRejected ||
		got[1] != pairExpiryContextPeerNeverObserved {
		t.Fatalf("post-prune classification = %v", got)
	}
}
