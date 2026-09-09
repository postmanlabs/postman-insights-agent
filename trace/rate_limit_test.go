package trace

import (
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/memview"
	"github.com/google/uuid"
	"github.com/postmanlabs/postman-insights-agent/capturestats"
	"github.com/spf13/viper"
)

type countingCollector struct {
	Mutex      sync.Mutex
	NumPackets int
}

func (c *countingCollector) Process(_ akinet.ParsedNetworkTraffic) error {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	c.NumPackets += 1
	return nil
}

func (c *countingCollector) Close() error {
	return nil
}

func (c *countingCollector) GetNumPackets() int {
	c.Mutex.Lock()
	defer c.Mutex.Unlock()
	return c.NumPackets
}

func TestRateLimit_FirstSample(t *testing.T) {
	viper.Set("debug", true)

	// Create a rate limiter with an absurdly small limit,
	// feed it events, verify the stats are correct.
	// 1 packet per minute = 5 packets in epoch

	start := time.Now()
	cc := &countingCollector{}
	stats := capturestats.New()
	rl := NewRateLimit(1.0, stats)
	pc := NewPacketCounter()
	c := rl.NewCollector(cc, pc, stats, nil).(*rateLimitCollector)

	// Sample packet from another test
	streamID := uuid.New()
	makeRequest := func(i int) akinet.ParsedNetworkTraffic {
		return akinet.ParsedNetworkTraffic{
			Content: akinet.HTTPRequest{
				StreamID: streamID,
				Seq:      1203 + i,
				Method:   "POST",
				URL: &url.URL{
					Path: "/v1/doggos",
				},
				Host: "example.com",
				Header: map[string][]string{
					"Content-Type": {"application/json"},
				},
				Body: memview.New([]byte(`{"name": "prince", "number": 6119717375543385000}`)),
			},
			ObservationTime: time.Now(),
			FinalPacketTime: time.Now(),
		}
	}

	// Wait for interval to start
	for !rl.IntervalStarted() {
		time.Sleep(1 * time.Millisecond)
	}

	for i := 0; i < 10; i++ {
		c.Process(makeRequest(i))
	}

	// If we read from the collector directly, the race checker will yell at us.
	// So, we'll ensure that at least 5 packets have been delivered before closing.
	ticker := time.NewTicker(10 * time.Millisecond)
	for cc.GetNumPackets() < 5 {
		<-ticker.C
	}

	c.Close()

	end := time.Now()
	fullDuration := end.Sub(start)

	if rl.SampleIntervalCount != 0 {
		t.Errorf("Expected packet counter to be zero, got %v", rl.SampleIntervalCount)
	}
	if cc.GetNumPackets() != 5 {
		t.Errorf("Expected 5 packets in collector, got %v", cc.GetNumPackets())
	}
	if pc.total.HTTPRequestsRateLimited != 5 {
		t.Errorf("Expected 5 rate limited request, got %v", pc.total.HTTPRequestsRateLimited)
	}
	if got := stats.Snapshot().RequestsRateLimited; got != 5 {
		t.Errorf("Expected 5 rate limited request telemetry counts, got %v", got)
	}
	if rl.FirstEstimate {
		t.Errorf("Expected FirstEstimate to be false")
	}
	if rl.EstimatedSampleInterval > fullDuration || rl.EstimatedSampleInterval == 0.0 {
		t.Errorf("Expected estimate to be less than %v, got %v", fullDuration, rl.EstimatedSampleInterval)
	}
	if len(c.RequestArrivalTimes) != 5 {
		t.Errorf("Expected 5 requests in ArrivalTimes, got %v", len(c.RequestArrivalTimes))
	}
	if len(rl.children) != 0 {
		t.Errorf("Expected empty child list after close.")
	}
}

func TestRateLimit_ClassifiesUnmatchedResponses(t *testing.T) {
	stats := capturestats.New()
	rl := NewRateLimit(1.0, stats)
	c := rl.NewCollector(&countingCollector{}, NewPacketCounter(), stats, nil).(*rateLimitCollector)
	defer rl.Stop()

	rateLimitedStream := uuid.New()
	expiredStream := uuid.New()
	activeStream := uuid.New()
	c.RateLimitedRequestKeys[requestKey{rateLimitedStream.String(), 1}] = time.Now()
	c.ExpiredRequestKeys[requestKey{expiredStream.String(), 2}] = time.Now()
	c.ActiveRequestStreams[activeStream.String()] = 1

	for _, response := range []akinet.HTTPResponse{
		{StreamID: rateLimitedStream, Seq: 1},
		{StreamID: expiredStream, Seq: 2},
		{StreamID: activeStream, Seq: 3},
		{StreamID: uuid.New(), Seq: 4},
	} {
		if err := c.Process(akinet.ParsedNetworkTraffic{Content: response}); err != nil {
			t.Fatalf("processing unmatched response: %v", err)
		}
	}

	snapshot := stats.Snapshot()
	if got := snapshot.ResponsesDroppedNoMatchingRequest; got != 4 {
		t.Fatalf("expected four unmatched responses, got %d", got)
	}
	// The fourth response has no tombstone, no active stream, and this
	// collector was built without a connection-context tracker, so it is
	// reported as context_unavailable rather than being folded into unknown.
	if snapshot.ResponsesDroppedNoMatchingRequestRateLimited != 1 ||
		snapshot.ResponsesDroppedNoMatchingRequestExpired != 1 ||
		snapshot.ResponsesDroppedNoMatchingRequestActiveRequestStream != 1 ||
		snapshot.ResponsesDroppedNoMatchingRequestContextUnavailable != 1 ||
		snapshot.ResponsesDroppedNoMatchingRequestUnknown != 0 {
		t.Fatalf("unexpected unmatched-response classifications: %+v", snapshot)
	}
}

func TestRateLimit_ExpiresRequestKeyBeforeClassifyingResponse(t *testing.T) {
	stats := capturestats.New()
	rl := NewRateLimit(1.0, stats)
	c := rl.NewCollector(&countingCollector{}, NewPacketCounter(), stats, nil).(*rateLimitCollector)
	defer rl.Stop()

	streamID := uuid.New()
	key := requestKey{streamID.String(), 1}
	c.RequestArrivalTimes[key] = time.Now().Add(-time.Minute)
	c.ActiveRequestStreams[key.StreamID] = 1
	c.expireRequests(time.Now())

	if err := c.Process(akinet.ParsedNetworkTraffic{Content: akinet.HTTPResponse{StreamID: streamID, Seq: 1}}); err != nil {
		t.Fatalf("processing expired response: %v", err)
	}

	snapshot := stats.Snapshot()
	if snapshot.RequestKeysExpired != 1 || snapshot.ResponsesDroppedNoMatchingRequestExpired != 1 {
		t.Fatalf("unexpected expiration counters: %+v", snapshot)
	}
}

func TestRateLimit_ClassifiesUnmatchedResponsesByConnectionContext(t *testing.T) {
	stats := capturestats.New()
	rl := NewRateLimit(1.0, stats)
	tracker := NewConnectionContextTracker(stats)
	local := rl.NewCollector(&countingCollector{}, NewPacketCounter(), stats, tracker).(*rateLimitCollector)
	other := rl.NewCollector(&countingCollector{}, NewPacketCounter(), stats, tracker).(*rateLimitCollector)
	defer rl.Stop()

	streamID := uuid.New()
	request := akinet.ParsedNetworkTraffic{
		SrcIP: net.IPv4(10, 0, 0, 1), SrcPort: 8080,
		DstIP: net.IPv4(10, 0, 0, 2), DstPort: 50000,
		Content: akinet.HTTPRequest{StreamID: streamID, Seq: 1},
	}
	tracker.observeRequest(request, local.collectorID)
	response := request
	response.SrcIP, response.DstIP = request.DstIP, request.SrcIP
	response.SrcPort, response.DstPort = request.DstPort, request.SrcPort
	response.Content = akinet.HTTPResponse{StreamID: streamID, Seq: 2}

	if err := local.Process(response); err != nil {
		t.Fatalf("processing local response: %v", err)
	}
	if err := other.Process(response); err != nil {
		t.Fatalf("processing other collector response: %v", err)
	}

	response.SrcPort = 50001
	if err := local.Process(response); err != nil {
		t.Fatalf("processing response-first response: %v", err)
	}
	if err := local.Process(akinet.ParsedNetworkTraffic{Content: akinet.HTTPResponse{StreamID: streamID, Seq: 3}}); err != nil {
		t.Fatalf("processing contextless response: %v", err)
	}

	snapshot := stats.Snapshot()
	if snapshot.ResponsesDroppedNoMatchingRequestRequestSeenLocalCollector != 1 ||
		snapshot.ResponsesDroppedNoMatchingRequestRequestSeenOtherCollector != 1 ||
		snapshot.ResponsesDroppedNoMatchingRequestResponseFirst != 1 ||
		snapshot.ResponsesDroppedNoMatchingRequestContextKeyInvalid != 1 ||
		snapshot.ResponsesDroppedNoMatchingRequestUnknown != 0 {
		t.Fatalf("unexpected connection-context classifications: %+v", snapshot)
	}
}

// A response whose key does not match the request we admitted on its own TCP
// stream must be attributed to that stream, not to the connection-context
// classifier's response_first. Before SeenRequestStreams existed, the
// admitted request was already gone from ActiveRequestStreams by the time the
// mismatched response arrived, so this case was reported as though the
// request had never been captured at all.
func TestRateLimit_AttributesKeyMismatchToSameStream(t *testing.T) {
	stats := capturestats.New()
	rl := NewRateLimit(100.0, stats)
	tracker := NewConnectionContextTracker(stats)
	c := rl.NewCollector(&countingCollector{}, NewPacketCounter(), stats, tracker).(*rateLimitCollector)
	defer rl.Stop()

	for !rl.IntervalStarted() {
		time.Sleep(1 * time.Millisecond)
	}

	streamID := uuid.New()
	traffic := func(content akinet.ParsedNetworkContent) akinet.ParsedNetworkTraffic {
		return akinet.ParsedNetworkTraffic{
			SrcIP: net.IPv4(10, 0, 0, 1), SrcPort: 8080,
			DstIP: net.IPv4(10, 0, 0, 2), DstPort: 50000,
			Content:         content,
			ObservationTime: time.Now(),
		}
	}

	// Admit a request, then let its own response pair with it. That empties
	// ActiveRequestStreams for this stream, which is the state the old code
	// could not distinguish from "no request was ever seen here".
	if err := c.Process(traffic(akinet.HTTPRequest{StreamID: streamID, Seq: 1})); err != nil {
		t.Fatalf("processing request: %v", err)
	}
	if err := c.Process(traffic(akinet.HTTPResponse{StreamID: streamID, Seq: 1})); err != nil {
		t.Fatalf("processing matching response: %v", err)
	}
	if got := c.ActiveRequestStreams[streamID.String()]; got != 0 {
		t.Fatalf("expected no active requests on the stream, got %d", got)
	}

	// A later response on the same stream whose key matches nothing.
	if err := c.Process(traffic(akinet.HTTPResponse{StreamID: streamID, Seq: 9999})); err != nil {
		t.Fatalf("processing mismatched response: %v", err)
	}

	snapshot := stats.Snapshot()
	if snapshot.ResponsesDroppedNoMatchingRequestRequestSeenSameStream != 1 {
		t.Fatalf("expected one same-stream attribution, got %+v", snapshot)
	}
	if snapshot.ResponsesDroppedNoMatchingRequestResponseFirst != 0 ||
		snapshot.ResponsesDroppedNoMatchingRequestRequestSeenLocalCollector != 0 {
		t.Fatalf("mismatched response should not reach the connection-context classifier: %+v", snapshot)
	}
}

// Once the stream's entry ages out, the same mismatched response falls
// through to the connection-context classifier again -- the retained set must
// not claim knowledge it has pruned.
func TestRateLimit_ExpiresSeenRequestStreams(t *testing.T) {
	stats := capturestats.New()
	rl := NewRateLimit(1.0, stats)
	c := rl.NewCollector(&countingCollector{}, NewPacketCounter(), stats, nil).(*rateLimitCollector)
	defer rl.Stop()

	streamID := uuid.New()
	c.SeenRequestStreams[streamID.String()] = time.Now().Add(-time.Hour)
	c.expireRequests(time.Now())

	if _, ok := c.SeenRequestStreams[streamID.String()]; ok {
		t.Fatalf("expected stale stream entry to be pruned")
	}

	if err := c.Process(akinet.ParsedNetworkTraffic{Content: akinet.HTTPResponse{StreamID: streamID, Seq: 1}}); err != nil {
		t.Fatalf("processing response: %v", err)
	}
	if got := stats.Snapshot().ResponsesDroppedNoMatchingRequestRequestSeenSameStream; got != 0 {
		t.Fatalf("expected no same-stream attribution after pruning, got %d", got)
	}
}

// The two halves of the key-mismatch story must meet: a response the rate
// limiter discards as unmatched has to become visible to the pair cache, so a
// request-only witness expiring on that same stream is attributed to a
// rejected companion rather than to "no response ever arrived".
func TestRateLimit_PublishesUnmatchedResponsesForPairExpiry(t *testing.T) {
	stats := capturestats.New()
	rl := NewRateLimit(1.0, stats)
	tracker := NewConnectionContextTracker(stats)
	c := rl.NewCollector(&countingCollector{}, NewPacketCounter(), stats, tracker).(*rateLimitCollector)
	defer rl.Stop()

	streamID := uuid.New()
	if err := c.Process(akinet.ParsedNetworkTraffic{
		SrcIP: net.IPv4(10, 0, 0, 2), SrcPort: 50000,
		DstIP: net.IPv4(10, 0, 0, 1), DstPort: 8080,
		Content: akinet.HTTPResponse{StreamID: streamID, Seq: 1},
	}); err != nil {
		t.Fatalf("processing unmatched response: %v", err)
	}

	streamKey, ok := streamContextKey(streamID)
	if !ok {
		t.Fatal("expected a usable stream key")
	}
	if got := tracker.classifyPairExpiries([]uint64{streamKey}); got[0] != pairExpiryContextPeerRejected {
		t.Fatalf("expiry on the rejected response's stream classified as %d, want peer rejected", got[0])
	}
}

// Even an unmatched response that an exact tombstone already explains was
// still captured and then discarded before it could pair, so it must publish
// to the stream index too.
func TestRateLimit_PublishesTombstonedUnmatchedResponses(t *testing.T) {
	stats := capturestats.New()
	rl := NewRateLimit(1.0, stats)
	tracker := NewConnectionContextTracker(stats)
	c := rl.NewCollector(&countingCollector{}, NewPacketCounter(), stats, tracker).(*rateLimitCollector)
	defer rl.Stop()

	streamID := uuid.New()
	c.RateLimitedRequestKeys[requestKey{streamID.String(), 1}] = time.Now()

	if err := c.Process(akinet.ParsedNetworkTraffic{
		Content: akinet.HTTPResponse{StreamID: streamID, Seq: 1},
	}); err != nil {
		t.Fatalf("processing unmatched response: %v", err)
	}

	if got := stats.Snapshot().ResponsesDroppedNoMatchingRequestRateLimited; got != 1 {
		t.Fatalf("expected the rate-limited tombstone to claim the drop, got %d", got)
	}
	streamKey, _ := streamContextKey(streamID)
	if got := tracker.classifyPairExpiries([]uint64{streamKey}); got[0] != pairExpiryContextPeerRejected {
		t.Fatalf("tombstoned drop classified as %d, want peer rejected", got[0])
	}
}
