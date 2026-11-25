package javatls

import (
	"strconv"
	"strings"
)

// Control is the content of the control file (ControlFilePath).
type Control struct {
	// Enabled switches capture on. When false, the Java agent stays dormant:
	// its hooks return at once and copy nothing.
	Enabled bool

	// CaptureCap, when nonzero, replaces the agent's per-frame payload cap.
	// The agent clamps it to at most DefaultCaptureCap.
	CaptureCap int
}

// Marshal returns the control file's content.
//
// Writers must replace the file atomically (write a temporary file in the same
// directory, then rename it over the old one), so the Java agent never reads
// a partly written file. The agent treats a file it cannot parse as missing.
func (c Control) Marshal() []byte {
	var b strings.Builder
	line := func(k, v string) {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte('\n')
	}
	line(ControlKeyVersion, ControlVersion1)
	if c.Enabled {
		line(ControlKeyEnabled, "1")
	} else {
		line(ControlKeyEnabled, "0")
	}
	if c.CaptureCap > 0 {
		line(ControlKeyCaptureCap, strconv.Itoa(c.CaptureCap))
	}
	return []byte(b.String())
}
