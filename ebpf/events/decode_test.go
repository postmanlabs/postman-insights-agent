// SPDX-License-Identifier: Apache-2.0

package events

import (
	"encoding/binary"
	"errors"
	"os"
	"regexp"
	"strconv"
	"testing"
)

// rawRecord builds a ring buffer record of size bytes with the given kind
// and payload, laid out like struct ssl_event / struct control_event.
func rawRecord(size int, kind uint8, payload string) []byte {
	raw := make([]byte, size)
	binary.LittleEndian.PutUint32(raw[8:], 42)                    // pid
	binary.LittleEndian.PutUint64(raw[16:], 1<<63|7)              // ssl_ctx
	binary.LittleEndian.PutUint32(raw[24:], uint32(len(payload))) // len_captured
	raw[37] = kind
	binary.LittleEndian.PutUint32(raw[40:], 4026531840) // netns
	copy(raw[rawHeaderSize:], payload)
	return raw
}

// Control events are the smaller struct control_event; data events must be
// a full struct ssl_event.
func TestDecodeControlEvent(t *testing.T) {
	// 44 bytes of fields and a 1024-byte payload, which C pads to 1072, a
	// multiple of the struct's 8-byte alignment.
	if rawHeaderSize != 44 || rawControlEventSize != 1072 {
		t.Fatalf("header %d, control event %d: out of step with event.h", rawHeaderSize, rawControlEventSize)
	}
	ev, err := Decode(rawRecord(rawControlEventSize, KindJavaHeartbeat, "state=active\n"))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Kind != KindJavaHeartbeat || ev.PID != 42 || ev.SSLCtx != 1<<63|7 || ev.NetNS != 4026531840 || string(ev.Bytes()) != "state=active\n" {
		t.Errorf("decoded %+v", ev)
	}

	if _, err := Decode(rawRecord(rawControlEventSize, KindData, "GET")); !errors.Is(err, ErrShortRecord) {
		t.Errorf("a data event of control size decoded: %v", err)
	}
	if _, err := Decode(rawRecord(rawControlEventSize-1, KindJavaHeartbeat, "state=active\n")); !errors.Is(err, ErrShortRecord) {
		t.Errorf("a truncated control event decoded: %v", err)
	}
	if _, err := Decode(rawRecord(rawHeaderSize, KindJavaClose, "")); !errors.Is(err, ErrShortRecord) {
		t.Errorf("a header-only record decoded: %v", err)
	}
	ev, err = Decode(rawRecord(rawEventSize, KindData, "GET /"))
	if err != nil || ev.Kind != KindData || string(ev.Bytes()) != "GET /" {
		t.Errorf("data event: %+v, %v", ev, err)
	}
}

// TestEventConstantsInSync checks the event kinds and payload sizes against
// event.h.
func TestEventConstantsInSync(t *testing.T) {
	raw, err := os.ReadFile("../programs/event.h")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, m := range regexp.MustCompile(`(?m)^#define\s+(\w+)\s+(\d+)`).FindAllStringSubmatch(string(raw), -1) {
		v, err := strconv.Atoi(m[2])
		if err != nil {
			t.Fatal(err)
		}
		got[m[1]] = v
	}
	for name, want := range map[string]int{
		"DIR_EGRESS":                int(DirEgress),
		"DIR_INGRESS":               int(DirIngress),
		"EVENT_KIND_DATA":           int(KindData),
		"EVENT_KIND_JAVA_HEARTBEAT": int(KindJavaHeartbeat),
		"EVENT_KIND_JAVA_CLOSE":     int(KindJavaClose),
		"MAX_EVENT_PAYLOAD":         MaxEventPayload,
		"MAX_CONTROL_PAYLOAD":       MaxControlPayload,
	} {
		if g, ok := got[name]; !ok || g != want {
			t.Errorf("%s: event.h has %d (defined: %v), Go has %d", name, g, ok, want)
		}
	}
}
