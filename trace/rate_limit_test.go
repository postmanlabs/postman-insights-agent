package trace

import (
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/memview"
	"github.com/google/uuid"
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
	rl := NewRateLimit(1.0)
	c := rl.NewCollector(cc, NewPacketCounter()).(*rateLimitCollector)

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
