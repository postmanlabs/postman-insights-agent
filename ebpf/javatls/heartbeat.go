// SPDX-License-Identifier: Apache-2.0

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
		num := func() uint64 {
			n, _ := strconv.ParseUint(v, 10, 64)
			return n
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
			h.Frames = num()
		case HeartbeatKeyDropped:
			h.Dropped = num()
		case HeartbeatKeyErrors:
			h.Errors = num()
		case HeartbeatKeyConnections:
			h.Connections = num()
		}
	}
	return h
}
