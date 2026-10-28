// SPDX-License-Identifier: Apache-2.0

package javatls

import "time"

// Names the Java agent and the Insights agent agree on, besides the frame
// format. The Java side mirrors these in
// java-agent/src/main/java/com/postman/insights/agent/bootstrap/Contract.java.

// AgentJarPath is where the Java agent jar lives in the Insights agent images.
const AgentJarPath = "/opt/postman/postman-java-agent.jar"

// MarkerProperty is the JVM system property the Java agent sets once its hooks
// are installed. Its value is the agent version. The attacher reads it to avoid
// loading a second copy into a JVM that already has the agent (static opt-in,
// or an earlier attach before an Insights agent restart).
const MarkerProperty = "postman.insights.agent.version"

// FailedProperty is the JVM system property the Java agent sets when it failed
// to start, as "<version>: <reason>". The agent does not retry in the same
// JVM, so the attacher should not either.
const FailedProperty = "postman.insights.agent.failed"

// Agent arguments are passed as comma-separated key=value pairs, for example
// "cap=16384". Unknown keys are ignored so that older agents accept arguments
// from newer Insights agents.
const (
	// ArgCaptureCap is the maximum number of payload bytes per frame.
	ArgCaptureCap = "cap"
)

// DefaultCaptureCap is the per-frame payload cap the Java agent uses when
// no cap argument is given. It matches MAX_EVENT_PAYLOAD in event.h, the most
// the kernel side keeps per event.
const DefaultCaptureCap = 16384

// The control file lets the Insights agent switch running Java agents on and
// off and change their capture cap. The Insights agent writes it inside each
// instrumented container and refreshes it periodically; the Java agent goes
// dormant when it is missing or stale. It holds key=value lines, one per line
// (see Control). The Java agent also stays dormant when the version is not
// one it knows, or when enabled is missing.
const (
	// ControlFilePath is the control file's path inside the container.
	ControlFilePath = "/tmp/.postman-insights/control"

	// ControlKeyVersion is the control-file format version (ControlVersion1).
	ControlKeyVersion = "version"
	// ControlKeyEnabled is "1" to capture, "0" to stay dormant.
	ControlKeyEnabled = "enabled"
	// ControlKeyCaptureCap overrides the per-frame payload cap, in bytes.
	ControlKeyCaptureCap = "cap_bytes"

	// ControlVersion1 is the only control-file format version so far.
	ControlVersion1 = "1"
)

const (
	// ControlRefreshInterval is how often the Insights agent rewrites the
	// control file.
	ControlRefreshInterval = 10 * time.Second
	// ControlStaleAfter is how old the control file may get before the Java
	// agent treats it as missing and goes dormant.
	ControlStaleAfter = 60 * time.Second
)

// AgentJarChecksumPath holds the SHA-256 of the agent jar, in sha256sum
// format, next to AgentJarPath in the Insights agent images.
const AgentJarChecksumPath = AgentJarPath + ".sha256"

// HEARTBEAT frames carry key=value lines (UTF-8, one per line) describing
// the Java agent. The agent sends one when it starts and then every
// HeartbeatInterval, whether it is capturing or dormant. Readers ignore
// unknown keys, so new keys need no frame version bump.
const (
	// HeartbeatKeyAgentVersion is the Java agent's version.
	HeartbeatKeyAgentVersion = "agent_version"
	// HeartbeatKeyJavaVersion and HeartbeatKeyJavaVendor are the JVM's
	// java.version and java.vendor system properties.
	HeartbeatKeyJavaVersion = "java_version"
	HeartbeatKeyJavaVendor  = "java_vendor"
	// HeartbeatKeySource is how the agent was loaded: HeartbeatSourceStatic
	// or HeartbeatSourceAttach.
	HeartbeatKeySource = "source"
	// HeartbeatKeyState is HeartbeatStateActive, HeartbeatStateDormant or
	// HeartbeatStateOff.
	HeartbeatKeyState = "state"
	// HeartbeatKeyFrames, HeartbeatKeyDropped and HeartbeatKeyErrors count
	// the traffic frames written, the frames not written (every frame buffer
	// was busy, or the application thread was interrupted), and the agent's
	// internal errors, since the agent started.
	HeartbeatKeyFrames  = "frames"
	HeartbeatKeyDropped = "dropped"
	HeartbeatKeyErrors  = "errors"
	// HeartbeatKeyConnections is the number of engines the agent is tracking.
	HeartbeatKeyConnections = "connections"
)

const (
	HeartbeatSourceStatic = "static" // -javaagent at JVM start
	HeartbeatSourceAttach = "attach" // dynamic attach

	// HeartbeatStateActive: capturing. HeartbeatStateDormant: not capturing,
	// because the control file is missing, stale or says enabled=0.
	// HeartbeatStateOff: the agent switched itself off after too many
	// internal errors, until the JVM restarts.
	HeartbeatStateActive  = "active"
	HeartbeatStateDormant = "dormant"
	HeartbeatStateOff     = "off"
)

// HeartbeatInterval is how often a Java agent sends a HEARTBEAT frame.
const HeartbeatInterval = 30 * time.Second
