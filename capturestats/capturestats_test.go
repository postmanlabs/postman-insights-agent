package capturestats

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// This is the regression test for the bug this package exists to fix: two
// independent capture sessions (e.g. two apidump.Run() goroutines on the same
// DaemonSet node, monitoring two different pods) must not observe each
// other's counters. A package-level `var Count... uint64`, which is what
// these counters used to be, would fail this test -- every increment on
// either Stats instance would land in the same global variable.
func TestStatsAreIsolatedPerSession(t *testing.T) {
	podA := New()
	podB := New()

	podA.IncrWitnessesPaired()
	podA.IncrWitnessesPaired()
	podA.IncrUnpairedRequestsFlushed()
	podA.AddPcapPacketsDropped(5)

	podB.IncrWitnessesPaired()
	podB.IncrResponsesDroppedNoMatchingRequest()

	snapA := podA.Snapshot()
	snapB := podB.Snapshot()

	assert.Equal(t, uint64(2), snapA.WitnessesPaired, "pod A's own pairs")
	assert.Equal(t, uint64(1), snapA.UnpairedRequestsFlushed)
	assert.Equal(t, uint64(5), snapA.PcapPacketsDropped)
	assert.Equal(t, uint64(0), snapA.ResponsesDroppedNoMatchingRequest, "must not see pod B's counters")

	assert.Equal(t, uint64(1), snapB.WitnessesPaired, "pod B's own pairs, not pod A's 2")
	assert.Equal(t, uint64(1), snapB.ResponsesDroppedNoMatchingRequest)
	assert.Equal(t, uint64(0), snapB.UnpairedRequestsFlushed, "must not see pod A's counters")
	assert.Equal(t, uint64(0), snapB.PcapPacketsDropped, "must not see pod A's counters")
}

// Every increment method, plus Snapshot and RecordNegativeLatency, must
// tolerate a nil *Stats without panicking -- callers thread this pointer
// through many layers (pcap, trace, apidump), and a nil one should be a
// silent no-op, not a crash of the capture pipeline.
func TestNilStatsIsSafe(t *testing.T) {
	var s *Stats

	assert.NotPanics(t, func() {
		s.AddPcapPacketsReceived(1)
		s.AddPcapPacketsDropped(1)
		s.AddPcapPacketsIfDropped(1)
		s.IncrNilAssemblerContext()
		s.IncrBadAssemblerContextType()
		s.IncrNilAssemblerContextAfterParse()
		s.IncrZeroValuePacketTimestamp()
		s.IncrLastPacketBeforeFirstPacket()
		s.AddReassemblyGapFlushed(1)
		s.IncrDiscardedRequests()
		s.IncrDiscardedResponses()
		s.IncrDiscardedOther()
		s.IncrResponsesDroppedNoMatchingRequest()
		s.IncrWitnessesPaired()
		s.IncrUnpairedRequestsFlushed()
		s.IncrUnpairedResponsesFlushed()
		s.IncrSameDirectionMerges()
		s.IncrNegativeLatencyUnder1ms()
		s.IncrNegativeLatencyUnder1s()
		s.IncrNegativeLatencyOver1s()
		s.IncrWitnessParseFailed()
		s.RecordNegativeLatency(-5000)
	})

	assert.Equal(t, Snapshot{}, s.Snapshot(), "nil Stats snapshots as all zeros")
}

// Increments from many goroutines must not race or lose updates -- every
// counter here is incremented from a different goroutine than the one that
// eventually reads it via Snapshot (e.g. pcap's reassembly goroutines vs. the
// apidump telemetry ticker).
func TestStatsConcurrentIncrements(t *testing.T) {
	s := New()
	const goroutines = 50
	const perGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range perGoroutine {
				s.IncrWitnessesPaired()
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, uint64(goroutines*perGoroutine), s.Snapshot().WitnessesPaired)
}

func TestRecordNegativeLatencyBuckets(t *testing.T) {
	s := New()
	s.RecordNegativeLatency(-0.5)   // under 1ms
	s.RecordNegativeLatency(-500)   // under 1s
	s.RecordNegativeLatency(-5000)  // over 1s
	s.RecordNegativeLatency(-999.9) // still under 1s

	snap := s.Snapshot()
	assert.Equal(t, uint64(1), snap.NegativeLatencyUnder1ms)
	assert.Equal(t, uint64(2), snap.NegativeLatencyUnder1s)
	assert.Equal(t, uint64(1), snap.NegativeLatencyOver1s)
}
