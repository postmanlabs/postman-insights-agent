// SPDX-License-Identifier: Apache-2.0

package javatls

import "time"

// Names the Java agent and the Insights agent agree on, besides the frame
// format. The Java side mirrors these in
// java-agent/src/main/java/com/postman/insights/agent/bootstrap/Contract.java.

// AgentJarPath is where the Java agent jar lives in the Insights agent images.
const AgentJarPath = "/opt/postman/postman-java-agent.jar"

// MarkerProperty is the JVM system property the Java agent sets once it is
// loaded. Its value is the agent version. The attacher reads it to avoid
// loading a second copy into a JVM that already has the agent (static opt-in,
// or an earlier attach before an Insights agent restart).
const MarkerProperty = "postman.insights.agent.version"

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
// dormant when it is missing or stale. It holds key=value lines, one per line.
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
