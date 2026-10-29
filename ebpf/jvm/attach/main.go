package attach

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// maxRequestSize bounds what the helper reads from stdin.
const maxRequestSize = 64 << 10

// run performs a request; Run, or a stand-in in tests.
var run = Run

// Main is the helper's main: it reads one Request from in, performs it, and
// writes the Result to out. It returns the exit code: 0 when a Result was
// written, whatever the outcome; 2 when the request could not be read.
func Main(in io.Reader, out io.Writer) int {
	raw, err := io.ReadAll(io.LimitReader(in, maxRequestSize+1))
	if err == nil && len(raw) > maxRequestSize {
		err = errors.New("request too large")
	}
	var req Request
	if err == nil {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		err = dec.Decode(&req)
		if err == nil {
			if _, tail := dec.Token(); tail != io.EOF {
				err = errors.New("data after the request")
			}
		}
	}
	// A request that does not decode cleanly is never performed, even when
	// every field it needs was decoded before the error.
	var res Result
	if err != nil {
		res = failed(ReasonBadRequest, false, "read request: %v", err)
	} else {
		res = run(req)
	}
	if err := json.NewEncoder(out).Encode(res); err != nil {
		return 2
	}
	if res.Reason == ReasonBadRequest {
		return 2
	}
	return 0
}

// StartTimeFromStat returns a process's start time, in clock ticks after
// boot, from the content of /proc/<pid>/stat (field 22).
func StartTimeFromStat(stat []byte) (uint64, error) {
	// The command (field 2) is in parentheses and may contain spaces and
	// parentheses itself, so fields are counted from the last ')'.
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		return 0, errors.New("malformed stat")
	}
	fields := strings.Fields(string(stat[end+1:]))
	// fields[0] is field 3 (state), so field 22 is fields[19].
	if len(fields) < 20 {
		return 0, fmt.Errorf("malformed stat: %d fields", len(fields)+2)
	}
	return strconv.ParseUint(fields[19], 10, 64)
}
