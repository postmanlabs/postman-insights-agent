package javatls

import (
	"encoding/json"
	"os"
	"testing"
)

type payloadVectors struct {
	Control []struct {
		Name      string `json:"name"`
		Canonical bool   `json:"canonical"`
		Content   string `json:"content"`
		Enabled   bool   `json:"enabled"`
		CapBytes  int    `json:"cap_bytes"`
	} `json:"control"`
	Heartbeat []struct {
		Name    string `json:"name"`
		Payload string `json:"payload"`
		Fields  struct {
			AgentVersion string `json:"agent_version"`
			JavaVersion  string `json:"java_version"`
			JavaVendor   string `json:"java_vendor"`
			Source       string `json:"source"`
			State        string `json:"state"`
			Frames       uint64 `json:"frames"`
			Dropped      uint64 `json:"dropped"`
			Errors       uint64 `json:"errors"`
			Connections  uint64 `json:"connections"`
		} `json:"fields"`
	} `json:"heartbeat"`
}

func loadPayloadVectors(t *testing.T) payloadVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/payloads-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v payloadVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestControlMarshal checks the writer against the canonical examples. The
// Java agent's tests parse every example.
func TestControlMarshal(t *testing.T) {
	n := 0
	for _, c := range loadPayloadVectors(t).Control {
		if !c.Canonical {
			continue
		}
		n++
		got := string(Control{Enabled: c.Enabled, CaptureCap: c.CapBytes}.Marshal())
		if got != c.Content {
			t.Errorf("%s: Marshal = %q, want %q", c.Name, got, c.Content)
		}
	}
	if n == 0 {
		t.Fatal("no canonical control examples")
	}
}

// TestParseHeartbeat decodes the example payloads. The Java agent's tests check it
// produces the canonical one.
func TestParseHeartbeat(t *testing.T) {
	examples := loadPayloadVectors(t).Heartbeat
	if len(examples) == 0 {
		t.Fatal("no HEARTBEAT examples")
	}
	for _, e := range examples {
		f := e.Fields
		want := Heartbeat{
			AgentVersion: f.AgentVersion,
			JavaVersion:  f.JavaVersion,
			JavaVendor:   f.JavaVendor,
			Source:       f.Source,
			State:        f.State,
			Frames:       f.Frames,
			Dropped:      f.Dropped,
			Errors:       f.Errors,
			Connections:  f.Connections,
		}
		if got := ParseHeartbeat([]byte(e.Payload)); got != want {
			t.Errorf("%s: ParseHeartbeat = %+v, want %+v", e.Name, got, want)
		}
	}
}

// TestHeartbeatFrameExample checks that the HEARTBEAT example frame carries a payload
// ParseHeartbeat understands.
func TestHeartbeatFrameExample(t *testing.T) {
	for _, vf := range loadVectors(t).Frames {
		if vf.Op != OpHeartbeat {
			continue
		}
		f, err := Parse(mustHex(t, vf.FrameHex))
		if err != nil {
			t.Fatal(err)
		}
		if h := ParseHeartbeat(f.Payload); h.AgentVersion == "" || h.State == "" {
			t.Errorf("HEARTBEAT example decodes to %+v", h)
		}
		return
	}
	t.Fatal("no HEARTBEAT example frame")
}
