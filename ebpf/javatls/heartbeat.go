package javatls

import (
	"strconv"
	"strings"
)

// Heartbeat is the decoded payload of a HEARTBEAT frame (see the HeartbeatKey
// constants). Fields the agent did not send are zero.
type Heartbeat struct {
	AgentVersion string
	JavaVersion  string
	JavaVendor   string
	Source       string
	State        string
	Frames       uint64
	Dropped      uint64
	Errors       uint64
	Connections  uint64
}

// ParseHeartbeat decodes a HEARTBEAT payload. It never fails: unknown keys,
// lines without '=' and malformed numbers are skipped, so newer agents'
// payloads still decode.
func ParseHeartbeat(payload []byte) Heartbeat {
	var h Heartbeat
	for _, line := range strings.Split(string(payload), "\n") {
		k, v, ok := strings.Cut(strings.TrimSuffix(line, "\r"), "=")
		if !ok {
			continue
		}
		// num sets *field only when v is a valid number, so a malformed
		// value never replaces a good one.
		num := func(field *uint64) {
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				*field = n
			}
		}
		switch k {
		case HeartbeatKeyAgentVersion:
			h.AgentVersion = v
		case HeartbeatKeyJavaVersion:
			h.JavaVersion = v
		case HeartbeatKeyJavaVendor:
			h.JavaVendor = v
		case HeartbeatKeySource:
			h.Source = v
		case HeartbeatKeyState:
			h.State = v
		case HeartbeatKeyFrames:
			num(&h.Frames)
		case HeartbeatKeyDropped:
			num(&h.Dropped)
		case HeartbeatKeyErrors:
			num(&h.Errors)
		case HeartbeatKeyConnections:
			num(&h.Connections)
		}
	}
	return h
}
