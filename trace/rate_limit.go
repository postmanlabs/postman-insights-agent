package trace

import (
	"math/rand"
	"sync"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/client_telemetry"
	"github.com/google/uuid"
	"github.com/postmanlabs/postman-insights-agent/capturestats"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/spf13/viper"
)

const (
	// One sample is collected per epoch
	RateLimitEpochTime = "rate-limit-epoch-time"

	// Maximum time to remember a request which we selected, but haven't seen a reaponse.
	RateLimitMaxDuration = "rate-limit-max-duration"

	// Channel size for packets coming in to collector
	RateLimitQueueDepth = "rate-limit-queue-depth"

	// Parameter controlling exponential moving average
	RateLimitExponentialAlpha = "rate-limit-exponential-alpha"
)

func init() {
	viper.SetDefault(RateLimitEpochTime, 5*time.Minute)
	viper.SetDefault(RateLimitMaxDuration, 10*time.Minute)
	viper.SetDefault(RateLimitQueueDepth, 1000)
	viper.SetDefault(RateLimitExponentialAlpha, 0.3)
}

type SharedRateLimit struct {
	// Current epoch: start time, sampling start time, count of witnesses captured
	CurrentEpochStart    time.Time
	SampleIntervalStart  time.Time
	SampleIntervalActive bool
	SampleIntervalCount  int

	// Time for epoch and interval
	epochTicker   *time.Ticker
	intervalTimer *time.Timer

	// Witnesses per minute (configured value) and per epoch (derived value)
	WitnessesPerMinute float64
	WitnessesPerEpoch  int

	// Current estimate of time taken to capture WitnessesPerEpoch
	EstimatedSampleInterval time.Duration
	FirstEstimate           bool

	// Channel for signaling goroutine to exit
	done chan struct{}

	// Child collectors
	children []*rateLimitCollector

	lock sync.Mutex

	// Capture-diagnostics counters for the apidump session that owns this
	// rate limit. One SharedRateLimit is created per apidump.Run() call, so
	// stats being a field here (rather than a package-level counter) is what
	// keeps a response we drop -- see the else branch in Process below --
	// attributed to the pod it actually belongs to.
	stats *capturestats.Stats
}

func (r *SharedRateLimit) startInterval(start time.Time) {
	// If we're in the current interval, just reset and keeping going.
	// We don't get an updated interval that way, but that's OK.
	printer.Debugln("New sample interval started:", start)

	r.lock.Lock()
	defer r.lock.Unlock()
	r.SampleIntervalStart = start
	r.SampleIntervalCount = 0
	r.SampleIntervalActive = true
}

func (r *SharedRateLimit) IntervalStarted() bool {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.SampleIntervalActive
}

// End the current interval and update the estimate; should be called with
// r.Lock already held.
func (r *SharedRateLimit) endInterval(end time.Time) {
	printer.Debugln("End of sample interval:", end)
	intervalLength := end.Sub(r.SampleIntervalStart)
	r.SampleIntervalActive = false
	r.SampleIntervalCount = 0

	if r.FirstEstimate {
		r.EstimatedSampleInterval = intervalLength
		r.FirstEstimate = false
	} else {
		alpha := viper.GetFloat64(RateLimitExponentialAlpha)
		exponentialMovingAverage := (1-alpha)*float64(r.EstimatedSampleInterval) + alpha*float64(intervalLength)
		printer.Debugln("New estimate:", exponentialMovingAverage)
		r.EstimatedSampleInterval = time.Duration(uint64(exponentialMovingAverage))
	}
}

// Run should immediately starts a measurement interval for the first epoch;
// without an estimate we should start capturing right away on the assumption we'll stay
// below the limit.
func (r *SharedRateLimit) run() {
	r.epochTicker = time.NewTicker(viper.GetDuration(RateLimitEpochTime))
	defer r.epochTicker.Stop()

	r.intervalTimer = time.NewTimer(0)
	defer r.intervalTimer.Stop()

	// Main loop: handle time events or shutdown
	for {
		select {
		case <-r.done:
			return
		case epochStart := <-r.epochTicker.C:
			r.startNewEpoch(epochStart)
		case intervalStart := <-r.intervalTimer.C:
			r.startInterval(intervalStart)
		}
	}
}

func (r *SharedRateLimit) Stop() {
	close(r.done)
}

func (r *SharedRateLimit) startNewEpoch(epochStart time.Time) {
	printer.Debugln("New collection epoch:", epochStart)

	r.lock.Lock()
	defer r.lock.Unlock()

	r.CurrentEpochStart = time.Now()

	// Ensure timer is stopped before reset
	// I *think* we don't need to drain the channel here (which would require
	// extra state to do reliably anyway.)
	r.intervalTimer.Stop()

	// Pick a time for the next sampling interval to start within this epoch.
	if r.FirstEstimate {
		// Didn't get a new estimate, just keep collecting everything.
		r.intervalTimer.Reset(0)
	} else {
		upperBound := viper.GetDuration(RateLimitEpochTime) - r.EstimatedSampleInterval
		randomOffset := time.Duration(rand.Int63n(int64(upperBound)))
		r.intervalTimer.Reset(randomOffset)
	}

	// Trigger request expiration for all collectors.
	// If they never have Process() called, then their channel will fill up,
	// so do this in a nonblocking fashion (with buffer size 1).
	threshold := epochStart.Add(-1 * viper.GetDuration(RateLimitMaxDuration))
	for _, child := range r.children {
		select {
		case child.epochCh <- threshold:
			continue
		default:
			printer.Debugf("child collector %p not accepting epoch start\n", child)
		}
	}
}

// Check if request should be sampled; increase the count by one.
func (r *SharedRateLimit) AllowHTTPRequest() bool {
	r.lock.Lock()
	defer r.lock.Unlock()
	if !r.SampleIntervalActive {
		return false
	}

	r.SampleIntervalCount += 1
	if r.SampleIntervalCount >= r.WitnessesPerEpoch {
		r.endInterval(time.Now())
	}
	return true
}

// Check if a non-HTTP packet should be sampled.
// All non-HTTP requests are passed through so they can
// be counted, if we're in an interval, but don't (yet) count
// against the witness budget.
// (For example, we might want to start counting source/dest pairs
// for HTTPS, or otherwise recording unparsable network traffic.)func (r *SharedRateLimit) AllowOther() bool {
func (r *SharedRateLimit) AllowOther() bool {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.SampleIntervalActive
}

type requestKey struct {
	StreamID       string
	SequenceNumber int
}

type rateLimitCollector struct {
	// Shared rate limit across all collectors
	// (typically one is created per interface, and for outgoing vs. incoming)
	RateLimit *SharedRateLimit

	// Next collector in stack
	NextCollector Collector

	// Map of unmatched request arrival times
	RequestArrivalTimes map[requestKey]time.Time

	// Recent rejected and expired request keys let us attribute an unmatched
	// response when its exact key is still known. Both maps are pruned on epoch
	// boundaries, so they cannot grow without bound.
	RateLimitedRequestKeys map[requestKey]time.Time
	ExpiredRequestKeys     map[requestKey]time.Time

	// Number of admitted requests still awaiting a response per TCP stream.
	// This is a factual diagnostic for an unmatched response with no exact
	// tombstone; it does not claim that the parser's request/response keys are
	// necessarily wrong.
	ActiveRequestStreams map[string]uint64

	// Last time a request was admitted on each TCP stream, retained after that
	// request leaves ActiveRequestStreams.
	//
	// ActiveRequestStreams alone cannot answer "did we ever see a request on
	// this stream", because removeActiveRequestStream deletes the entry as
	// soon as the request pairs or expires. A response whose key does not
	// match the request we admitted on its own stream therefore used to fall
	// through to the connection-context classifier and be reported as
	// response_first -- indistinguishable from a connection whose request we
	// genuinely never captured. This map keeps that distinction observable.
	//
	// Only admitted requests are recorded. A rate-limited request already has
	// an exact tombstone in RateLimitedRequestKeys, and its response *should*
	// be dropped, so folding it in here would mix correct behaviour into a
	// counter that exists to surface key mismatches.
	//
	// Bounded the same way RequestArrivalTimes is: keys are a subset of the
	// streams of admitted requests, which the rate limit itself caps per
	// epoch, and stale entries are pruned in expireRequests.
	SeenRequestStreams map[string]time.Time

	// Channel from RateLimit for epoch starts
	epochCh chan time.Time

	// Packet counter
	packetCount PacketCountConsumer

	stats *capturestats.Stats

	connectionContext *ConnectionContextTracker
	collectorID       uint64
}

// NewCollector creates a collector that shares this rate limit but records its
// diagnostics against one capture source. Stats are per-source rather than
// taken from the SharedRateLimit, because one rate limit is shared by the pcap
// and eBPF chains while their counters must not be.
func (r *SharedRateLimit) NewCollector(next Collector, packetCounts PacketCountConsumer, stats *capturestats.Stats, connectionContext *ConnectionContextTracker) Collector {
	c := &rateLimitCollector{
		RateLimit:              r,
		NextCollector:          next,
		RequestArrivalTimes:    make(map[requestKey]time.Time),
		RateLimitedRequestKeys: make(map[requestKey]time.Time),
		ExpiredRequestKeys:     make(map[requestKey]time.Time),
		ActiveRequestStreams:   make(map[string]uint64),
		SeenRequestStreams:     make(map[string]time.Time),
		epochCh:                make(chan time.Time, 1),
		packetCount:            packetCounts,
		stats:                  stats,
		connectionContext:      connectionContext,
	}
	c.collectorID = connectionContext.registerCollector()
	r.lock.Lock()
	defer r.lock.Unlock()
	r.children = append(r.children, c)
	return c
}

func (r *SharedRateLimit) onCollectorClose(closed *rateLimitCollector) {
	r.lock.Lock()
	defer r.lock.Unlock()
	for i, c := range r.children {
		if c == closed {
			r.children = append(r.children[:i], r.children[i+1:]...)
			return
		}
	}
}

func (r *rateLimitCollector) Process(pnt akinet.ParsedNetworkTraffic) error {
	switch c := pnt.Content.(type) {
	case akinet.HTTPRequest:
		r.connectionContext.observeRequest(pnt, r.collectorID)
		if r.RateLimit.AllowHTTPRequest() {
			// Collect request and the matching response as well.
			r.NextCollector.Process(pnt)
			key := requestKey{c.StreamID.String(), c.Seq}
			if _, alreadyTracked := r.RequestArrivalTimes[key]; !alreadyTracked {
				r.ActiveRequestStreams[key.StreamID] += 1
			}
			r.RequestArrivalTimes[key] = pnt.ObservationTime
			// Wall clock, not pnt.ObservationTime, so a zero or skewed packet
			// timestamp (see capturestats.ZeroValuePacketTimestamp) cannot make
			// this entry instantly prunable and silently restore the
			// misattribution it exists to prevent.
			r.SeenRequestStreams[key.StreamID] = time.Now()
		} else {
			key := requestKey{c.StreamID.String(), c.Seq}
			r.RateLimitedRequestKeys[key] = time.Now()
			r.stats.IncrRequestsRateLimited()
			r.packetCount.Update(client_telemetry.PacketCounts{
				Interface:               pnt.Interface,
				DstHost:                 c.Host,
				SrcPort:                 pnt.SrcPort,
				DstPort:                 pnt.DstPort,
				HTTPRequestsRateLimited: 1,
			})
		}
	case akinet.HTTPResponse:
		// Collect iff the request is in our map. (This means responses to calls
		// before the sampling interval will not be captured.)
		key := requestKey{c.StreamID.String(), c.Seq}
		if _, ok := r.RequestArrivalTimes[key]; ok {
			delete(r.RequestArrivalTimes, key)
			r.removeActiveRequestStream(key.StreamID)
			r.NextCollector.Process(pnt)
		} else {
			// We parsed this response but are throwing it away, because we cannot
			// match it to a request we admitted. Its request has already gone
			// downstream, so this becomes a witness with no response half, which
			// the back end drops as missing_status_code.
			//
			r.stats.IncrResponsesDroppedNoMatchingRequest()
			r.recordUnmatchedResponse(pnt, key, c.StreamID)
		}
	default:
		if r.RateLimit.AllowOther() {
			r.NextCollector.Process(pnt)
		}
	}

	// Check for new epoch, in a nonblocking way
	select {
	case epochStart := <-r.epochCh:
		r.expireRequests(epochStart)
	default:
		break
	}

	return nil
}

func (r *rateLimitCollector) Close() error {
	// Remove self from future epoch updates
	r.RateLimit.onCollectorClose(r)
	return r.NextCollector.Close()
}

// expire requests that came in before the threshold value
func (r *rateLimitCollector) expireRequests(threshold time.Time) {
	expired := 0
	for k, v := range r.RequestArrivalTimes {
		if v.Before(threshold) {
			delete(r.RequestArrivalTimes, k)
			r.removeActiveRequestStream(k.StreamID)
			// Retain from the expiration point, not the original arrival time;
			// otherwise the cleanup loop below removes the tombstone immediately.
			r.ExpiredRequestKeys[k] = time.Now()
			expired += 1
		}
	}
	for k, v := range r.RateLimitedRequestKeys {
		if v.Before(threshold) {
			delete(r.RateLimitedRequestKeys, k)
		}
	}
	for k, v := range r.ExpiredRequestKeys {
		if v.Before(threshold) {
			delete(r.ExpiredRequestKeys, k)
		}
	}
	for k, v := range r.SeenRequestStreams {
		if v.Before(threshold) {
			delete(r.SeenRequestStreams, k)
		}
	}
	r.stats.AddRequestKeysExpired(uint64(expired))
	printer.Debugf("Expired %v old requests\n", expired)
}

func (r *rateLimitCollector) recordUnmatchedResponse(pnt akinet.ParsedNetworkTraffic, key requestKey, streamID uuid.UUID) {
	// Publish the drop against its stream before classifying it. This is the
	// companion evidence a witness expiring unpaired later looks up (see
	// ConnectionContextTracker.classifyPairExpiries), and it is recorded for
	// every unmatched response regardless of which bucket below claims it: a
	// response explained by an exact tombstone was still captured and then
	// discarded before it could complete a pair.
	r.connectionContext.observeUnmatchedResponse(streamID)

	if _, ok := r.RateLimitedRequestKeys[key]; ok {
		delete(r.RateLimitedRequestKeys, key)
		r.stats.IncrResponsesDroppedNoMatchingRequestRateLimited()
		return
	}
	if _, ok := r.ExpiredRequestKeys[key]; ok {
		delete(r.ExpiredRequestKeys, key)
		r.stats.IncrResponsesDroppedNoMatchingRequestExpired()
		return
	}
	if r.ActiveRequestStreams[key.StreamID] > 0 {
		r.stats.IncrResponsesDroppedNoMatchingRequestActiveRequestStream()
		return
	}
	// Checked before the connection-context classifier because it is the
	// stronger claim: a TCP stream identifies one connection, while the
	// classifier's key is a normalized address pair that a later connection
	// can reuse. Reaching here means we admitted a request on this very
	// stream and this response's key still did not match it -- so the request
	// was captured and the two keys disagree, which is what
	// response_first would otherwise have denied.
	if _, ok := r.SeenRequestStreams[key.StreamID]; ok {
		r.stats.IncrResponsesDroppedNoMatchingRequestRequestSeenSameStream()
		return
	}
	switch r.connectionContext.classifyResponse(pnt, r.collectorID) {
	case unmatchedResponseContextResponseFirst:
		r.stats.IncrResponsesDroppedNoMatchingRequestResponseFirst()
	case unmatchedResponseContextRequestSeenLocalCollector:
		r.stats.IncrResponsesDroppedNoMatchingRequestRequestSeenLocalCollector()
	case unmatchedResponseContextRequestSeenOtherCollector:
		r.stats.IncrResponsesDroppedNoMatchingRequestRequestSeenOtherCollector()
	case unmatchedResponseContextKeyInvalid:
		r.stats.IncrResponsesDroppedNoMatchingRequestContextKeyInvalid()
	case unmatchedResponseContextTrackerUnavailable:
		r.stats.IncrResponsesDroppedNoMatchingRequestContextUnavailable()
	default:
		// Only unmatchedResponseContextUnknown reaches here, which
		// classifyResponse no longer returns. Kept as a backstop so a reason
		// added there without a case here is counted rather than dropped.
		r.stats.IncrResponsesDroppedNoMatchingRequestUnknown()
	}
}

func (r *rateLimitCollector) removeActiveRequestStream(streamID string) {
	if r.ActiveRequestStreams[streamID] <= 1 {
		delete(r.ActiveRequestStreams, streamID)
		return
	}
	r.ActiveRequestStreams[streamID] -= 1
}

func NewRateLimit(witnessesPerMinute float64, stats *capturestats.Stats) *SharedRateLimit {
	witnessLimit := witnessesPerMinute * viper.GetDuration(RateLimitEpochTime).Minutes()
	if witnessLimit < 1 {
		printer.Warningln("Witnesses per minute rate is too low; rounding up to 1 per 5 minutes.")
		witnessLimit = 1
	}
	r := &SharedRateLimit{
		WitnessesPerMinute: witnessesPerMinute,
		WitnessesPerEpoch:  int(witnessLimit),
		FirstEstimate:      true,
		done:               make(chan struct{}),
		stats:              stats,
	}

	// Start the first epoch.
	// run() will start an interval immediately.
	r.CurrentEpochStart = time.Now()
	go r.run()
	return r
}
