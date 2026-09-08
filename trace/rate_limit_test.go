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
	if snapshot.ResponsesDroppedNoMatchingRequestRateLimited != 1 ||
		snapshot.ResponsesDroppedNoMatchingRequestExpired != 1 ||
		snapshot.ResponsesDroppedNoMatchingRequestActiveRequestStream != 1 ||
		snapshot.ResponsesDroppedNoMatchingRequestUnknown != 1 {
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
	tracker := NewConnectionContextTracker()
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
		snapshot.ResponsesDroppedNoMatchingRequestUnknown != 1 {
		t.Fatalf("unexpected connection-context classifications: %+v", snapshot)
	}
}
