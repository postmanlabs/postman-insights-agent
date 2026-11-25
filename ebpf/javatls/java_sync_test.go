package javatls

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const javaAgentDir = "../../java-agent/src/main/java/com/postman/insights/agent/"

// javaConstants returns the `static final` constants declared in a Java file,
// by name, as their literal source text (strings unquoted).
func javaConstants(t *testing.T, file string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(javaAgentDir + file)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	re := regexp.MustCompile(`static final \w+ (\w+) = ([^;]+);`)
	for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
		v := strings.TrimSpace(m[2])
		if unquoted, err := strconv.Unquote(v); err == nil {
			out[m[1]] = unquoted
			continue
		}
		v = strings.TrimPrefix(v, "(short) ")
		v = strings.TrimPrefix(v, "(byte) ")
		v = strings.TrimSuffix(v, "L")
		out[m[1]] = strings.ReplaceAll(v, "_", "")
	}
	return out
}

func checkJava(t *testing.T, file string, got map[string]string, want map[string]string) {
	t.Helper()
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("%s does not declare %s", file, name)
			continue
		}
		if gi, err := strconv.ParseInt(g, 0, 64); err == nil {
			if wi, err := strconv.ParseInt(w, 0, 64); err == nil && gi == wi {
				continue
			}
		}
		if g != w {
			t.Errorf("%s %s = %s, Go has %s", file, name, g, w)
		}
	}
}

func num(v uint64) string { return strconv.FormatUint(v, 10) }

// TestJavaFrameInSync checks Frame.java against this package.
func TestJavaFrameInSync(t *testing.T) {
	checkJava(t, "Frame.java", javaConstants(t, "bootstrap/Frame.java"), map[string]string{
		"MAGIC":             num(Magic),
		"VERSION_1":         num(uint64(Version1)),
		"HEADER_SIZE":       num(HeaderSize),
		"OP_SEND":           num(uint64(OpSend)),
		"OP_RECV":           num(uint64(OpRecv)),
		"OP_HEARTBEAT":      num(uint64(OpHeartbeat)),
		"OP_CLOSE":          num(uint64(OpClose)),
		"OP_ADDRESS":        num(uint64(OpAddress)),
		"ADDRESS_SIZE":      num(AddressSize),
		"FLAG_ROLE_KNOWN":   num(uint64(FlagRoleKnown)),
		"FLAG_CLIENT_MODE":  num(uint64(FlagClientMode)),
		"FLAG_SOCKET":       num(uint64(FlagSocket)),
		"FLAG_BEFORE_WRITE": num(uint64(FlagBeforeWrite)),
		"OFF_VERSION":       num(offVersion),
		"OFF_OP":            num(offOp),
		"OFF_FLAGS":         num(offFlags),
		"OFF_PAYLOAD_LEN":   num(offPayloadLen),
		"OFF_CONN_ID":       num(offConnID),
		"OFF_RESERVED":      num(offReserved),
		"OFF_TOTAL_LEN":     num(offTotalLen),
	})
}

// TestJavaContractInSync checks Contract.java against contract.go.
func TestJavaContractInSync(t *testing.T) {
	ms := func(d time.Duration) string { return num(uint64(d.Milliseconds())) }
	checkJava(t, "Contract.java", javaConstants(t, "bootstrap/Contract.java"), map[string]string{
		"MARKER_PROPERTY":                 MarkerProperty,
		"FAILED_PROPERTY":                 FailedProperty,
		"ARG_CAPTURE_CAP":                 ArgCaptureCap,
		"DEFAULT_CAPTURE_CAP":             num(DefaultCaptureCap),
		"CONTROL_FILE_PATH":               ControlFilePath,
		"CONTROL_KEY_VERSION":             ControlKeyVersion,
		"CONTROL_KEY_ENABLED":             ControlKeyEnabled,
		"CONTROL_KEY_CAPTURE_CAP":         ControlKeyCaptureCap,
		"CONTROL_VERSION_1":               ControlVersion1,
		"CONTROL_REFRESH_INTERVAL_MILLIS": ms(ControlRefreshInterval),
		"CONTROL_STALE_AFTER_MILLIS":      ms(ControlStaleAfter),
		"HEARTBEAT_KEY_AGENT_VERSION":     HeartbeatKeyAgentVersion,
		"HEARTBEAT_KEY_JAVA_VERSION":      HeartbeatKeyJavaVersion,
		"HEARTBEAT_KEY_JAVA_VENDOR":       HeartbeatKeyJavaVendor,
		"HEARTBEAT_KEY_SOURCE":            HeartbeatKeySource,
		"HEARTBEAT_KEY_STATE":             HeartbeatKeyState,
		"HEARTBEAT_KEY_FRAMES":            HeartbeatKeyFrames,
		"HEARTBEAT_KEY_DROPPED":           HeartbeatKeyDropped,
		"HEARTBEAT_KEY_ERRORS":            HeartbeatKeyErrors,
		"HEARTBEAT_KEY_CONNECTIONS":       HeartbeatKeyConnections,
		"HEARTBEAT_SOURCE_STATIC":         HeartbeatSourceStatic,
		"HEARTBEAT_SOURCE_ATTACH":         HeartbeatSourceAttach,
		"HEARTBEAT_STATE_ACTIVE":          HeartbeatStateActive,
		"HEARTBEAT_STATE_DORMANT":         HeartbeatStateDormant,
		"HEARTBEAT_STATE_OFF":             HeartbeatStateOff,
		"HEARTBEAT_INTERVAL_MILLIS":       ms(HeartbeatInterval),
	})
}

// TestJavaAgentMainInSync checks AgentMain's private copies of the property
// names (it cannot use Contract before the bootstrap class path is set up).
func TestJavaAgentMainInSync(t *testing.T) {
	checkJava(t, "AgentMain.java", javaConstants(t, "AgentMain.java"), map[string]string{
		"MARKER_PROPERTY": MarkerProperty,
		"FAILED_PROPERTY": FailedProperty,
	})
}
