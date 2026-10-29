package loader

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// TestJavaCountersInSync checks the JavaCounter* indices against JAVA_CTR_*
// in java_tls.bpf.c. Runs without the insights_bpf tag.
func TestJavaCountersInSync(t *testing.T) {
	raw, err := os.ReadFile("../programs/java_tls.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]uint32{
		"JAVA_CTR_FRAMES_SEEN":       JavaCounterFramesSeen,
		"JAVA_CTR_EVENTS_EMITTED":    JavaCounterEventsEmitted,
		"JAVA_CTR_EVENTS_DROPPED":    JavaCounterEventsDropped,
		"JAVA_CTR_READ_FAILED":       JavaCounterReadFailed,
		"JAVA_CTR_BYTES_CAPTURED":    JavaCounterBytesCaptured,
		"JAVA_CTR_RATE_CAPPED":       JavaCounterRateCapped,
		"JAVA_CTR_NETNS_REJECTED":    JavaCounterNetnsRejected,
		"JAVA_CTR_MALFORMED":         JavaCounterMalformed,
		"JAVA_CTR_CONTROL_FRAMES":    JavaCounterControlFrames,
		"JAVA_CTR_HEARTBEAT_LIMITED": JavaCounterHeartbeatLimited,
		"JAVA_CTR_CONN_BOUND":        JavaCounterConnBound,
		"JAVA_CTR_CONN_UNBOUND":      JavaCounterConnUnbound,
		"JAVA_CTR_CONN_MISMATCH":     JavaCounterConnMismatch,
		"JAVA_CTR_MAX":               uint32(13),
	}
	got := map[string]uint32{}
	for _, m := range regexp.MustCompile(`(?m)^#define\s+(JAVA_CTR_\w+)\s+(\d+)`).FindAllStringSubmatch(string(raw), -1) {
		v, err := strconv.ParseUint(m[2], 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		got[m[1]] = uint32(v)
	}
	if len(got) != len(want) {
		t.Errorf("java_tls.bpf.c defines %d JAVA_CTR_* constants, Go knows %d", len(got), len(want))
	}
	for name, w := range want {
		if g, ok := got[name]; !ok || g != w {
			t.Errorf("%s: java_tls.bpf.c has %d (defined: %v), Go has %d", name, g, ok, w)
		}
	}
}
