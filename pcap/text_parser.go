package pcap

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ParsedRequest represents a successfully parsed HTTP request (HTTP/1.1 or HTTP/2)
type ParsedRequest struct {
	StreamID  uuid.UUID
	Method    string
	Path      string
	Headers   map[string]string
	Body      []byte
	Version   string // "HTTP/1.1" or "HTTP/2"
	Timestamp time.Time
	EndStream bool
}

// ParsedResponse represents a successfully parsed HTTP response (HTTP/1.1 or HTTP/2)
type ParsedResponse struct {
	StreamID  uuid.UUID
	Status    int
	Headers   map[string]string
	Body      []byte
	Version   string // "HTTP/1.1" or "HTTP/2"
	Timestamp time.Time
	EndStream bool
}

// ParsedDataFrame represents HTTP/2 DATA frames
type ParsedDataFrame struct {
	StreamID   uuid.UUID
	Payload    []byte
	IsResponse bool
	EndStream  bool
	Timestamp  time.Time
}

// UnparsedRecord represents a frame that could not be parsed
// Used for telemetry/metrics without exposing full plaintext
type UnparsedRecord struct {
	Bytes     int    // Approximate byte count
	Protocol  string // Best guess: "HTTP/2", "HTTP/1.1", "Unknown"
	ErrorType string // "malformed_headers", "timeout", "buffer_overflow", etc.
	Timestamp time.Time
	RawSample string // First 200 chars for debugging (never full plaintext)
}

// RawFrame represents a logical frame from eCapture text output
type RawFrame struct {
	FrameType string   // "HEADERS", "DATA", "HTTP1_REQUEST", "HTTP1_RESPONSE"
	Lines     []string // Raw text lines
	Timestamp time.Time
}

// Protocol detection
type Protocol int

const (
	ProtocolUnknown Protocol = iota
	ProtocolHTTP1
	ProtocolHTTP2
)

// DetectProtocol examines the first few lines to determine HTTP/1.1 vs HTTP/2
func DetectProtocol(frame RawFrame) Protocol {
	if len(frame.Lines) == 0 {
		return ProtocolUnknown
	}

	// Scan lines to detect HTTP/2 markers even if a metadata line precedes the frame.
	for _, raw := range frame.Lines {
		line := strings.TrimSpace(raw)
		normalizedLine := strings.Join(strings.Fields(line), " ")
		if strings.HasPrefix(normalizedLine, "Frame Type =>") || strings.Contains(line, "Frame Type") && strings.Contains(line, "=>") {
			return ProtocolHTTP2
		}
	}

	firstLine := strings.TrimSpace(frame.Lines[0])

	// HTTP/1.1 Request: "GET /path HTTP/1.1"
	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"} {
		if strings.HasPrefix(firstLine, method+" ") {
			return ProtocolHTTP1
		}
	}

	// HTTP/1.1 Response: "HTTP/1.1 200 OK"
	if strings.HasPrefix(firstLine, "HTTP/1.") {
		return ProtocolHTTP1
	}

	return ProtocolUnknown
}

// ParseFrame is the main entry point for parsing
func ParseFrame(frame RawFrame) (interface{}, error) {
	protocol := DetectProtocol(frame)

	switch protocol {
	case ProtocolHTTP2:
		if strings.EqualFold(frame.FrameType, "DATA") {
			return ParseHTTP2DataFrame(frame)
		}
		return ParseHTTP2Frame(frame)
	case ProtocolHTTP1:
		firstLine := strings.TrimSpace(frame.Lines[0])
		if strings.HasPrefix(firstLine, "HTTP/1.") {
			return ParseHTTP1Response(frame)
		}
		return ParseHTTP1Request(frame)
	default:
		// Fallback: create unparsed record
		return CreateUnparsedRecord(frame, "unknown_protocol", nil), nil
	}
}

// ParseHTTP1Request parses HTTP/1.1 requests
func ParseHTTP1Request(frame RawFrame) (*ParsedRequest, error) {
	if len(frame.Lines) == 0 {
		return nil, errors.New("empty frame")
	}

	// Derive a deterministic stream ID based on any UUID marker in the frame
	streamID := deriveStreamID(frame)

	// Parse request line: "GET /path HTTP/1.1"
	requestLine := strings.TrimSpace(frame.Lines[0])
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid request line: %s", requestLine)
	}

	req := &ParsedRequest{
		StreamID:  streamID,
		Method:    parts[0],
		Path:      parts[1],
		Version:   parts[2],
		Headers:   make(map[string]string),
		Timestamp: frame.Timestamp,
	}

	// Parse headers (simple "Key: Value" format)
	bodyStart := -1
	for i := 1; i < len(frame.Lines); i++ {
		line := strings.TrimSpace(frame.Lines[i])

		// Empty line marks end of headers
		if line == "" {
			bodyStart = i + 1
			break
		}

		// Split on first ": "
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) == 2 {
			req.Headers[parts[0]] = parts[1]
		}
	}

	// Handle body (if Content-Length present)
	if bodyStart > 0 && bodyStart < len(frame.Lines) {
		if contentLen := req.Headers["Content-Length"]; contentLen != "" {
			length, err := strconv.Atoi(contentLen)
			if err == nil && length > 0 {
				// Accumulate remaining lines as body
				bodyLines := frame.Lines[bodyStart:]
				bodyText := strings.Join(bodyLines, "\n")
				req.Body = []byte(bodyText)

				// Trim to Content-Length if we have more data
				if len(req.Body) > length {
					req.Body = req.Body[:length]
				}
			}
		}
	}

	return req, nil
}

// ParseHTTP1Response parses HTTP/1.1 responses
func ParseHTTP1Response(frame RawFrame) (*ParsedResponse, error) {
	if len(frame.Lines) == 0 {
		return nil, errors.New("empty frame")
	}

	streamID := deriveStreamID(frame)

	// Parse status line: "HTTP/1.1 200 OK"
	statusLine := strings.TrimSpace(frame.Lines[0])
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid status line: %s", statusLine)
	}

	statusCode, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid status code: %s", parts[1])
	}

	resp := &ParsedResponse{
		StreamID:  streamID,
		Status:    statusCode,
		Version:   parts[0],
		Headers:   make(map[string]string),
		Timestamp: frame.Timestamp,
	}

	// Parse headers
	bodyStart := -1
	for i := 1; i < len(frame.Lines); i++ {
		line := strings.TrimSpace(frame.Lines[i])

		if line == "" {
			bodyStart = i + 1
			break
		}

		parts := strings.SplitN(line, ": ", 2)
		if len(parts) == 2 {
			resp.Headers[parts[0]] = parts[1]
		}
	}

	// Handle body (if Content-Length present)
	if bodyStart > 0 && bodyStart < len(frame.Lines) {
		if contentLen := resp.Headers["Content-Length"]; contentLen != "" {
			length, err := strconv.Atoi(contentLen)
			if err == nil && length > 0 {
				bodyLines := frame.Lines[bodyStart:]
				bodyText := strings.Join(bodyLines, "\n")
				resp.Body = []byte(bodyText)
				if len(resp.Body) > length {
					resp.Body = resp.Body[:length]
				}
			}
		}
	}

	return resp, nil
}

// ParseHTTP2Frame parses HTTP/2 HEADERS frames from eCapture text output
func ParseHTTP2Frame(frame RawFrame) (interface{}, error) {
	if len(frame.Lines) == 0 {
		return nil, errors.New("empty frame")
	}

	streamID := deriveStreamID(frame)

	// eCapture emits a metadata line followed by "Frame Type => HEADERS".
	// Find the first line that actually contains "Frame Type".
	startIdx := -1
	for i, l := range frame.Lines {
		if strings.Contains(strings.Join(strings.Fields(strings.TrimSpace(l)), " "), "Frame Type =>") {
			startIdx = i
			break
		}
	}
	if startIdx == -1 {
		return nil, fmt.Errorf("no frame type marker found")
	}

	lines := frame.Lines[startIdx:]

	// Verify this is a HEADERS frame (handle both spaces and tabs)
	firstLine := strings.TrimSpace(lines[0])
	normalizedFirst := strings.Join(strings.Fields(firstLine), " ")
	if !strings.Contains(normalizedFirst, "Frame Type") || !strings.Contains(normalizedFirst, "HEADERS") {
		return nil, fmt.Errorf("not a HEADERS frame: %s", firstLine)
	}

	headers := make(map[string]string)
	req := &ParsedRequest{
		StreamID:  streamID,
		Headers:   headers,
		Version:   "HTTP/2",
		Timestamp: frame.Timestamp,
	}
	resp := &ParsedResponse{
		StreamID:  streamID,
		Headers:   headers,
		Version:   "HTTP/2",
		Timestamp: frame.Timestamp,
	}

	// Track flags for END_STREAM
	var flagsLine string

	// Parse header fields
	// Format: header field "key" = "value" or header field\t"key"\t=\t"value" (with tabs)
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])

		// Stop at next frame or empty line
		if line == "" || strings.Contains(line, "Frame Type") {
			break
		}

		// Capture flags
		if strings.HasPrefix(line, "Flags") {
			flagsLine = line
		}

		// Parse: header field "key" = "value" (handle tabs and spaces)
		if !strings.Contains(line, "header field") {
			continue
		}

		// Normalize whitespace for parsing
		normalizedLine := strings.Join(strings.Fields(line), " ")

		// Remove "header field " prefix
		if !strings.HasPrefix(normalizedLine, "header field ") {
			continue
		}
		kvPart := normalizedLine[13:]

		// Split on " = " (after normalization)
		parts := strings.SplitN(kvPart, " = ", 2)
		if len(parts) != 2 {
			continue
		}

		// Remove quotes from key and value
		key := strings.Trim(parts[0], `"`)
		value := strings.Trim(parts[1], `"`)

		// Handle pseudo-headers
		switch key {
		case ":method":
			req.Method = value
		case ":path":
			req.Path = value
		case ":authority":
			headers["Host"] = value
		case ":scheme":
			headers["X-Scheme"] = value
		case ":status":
			statusCode, err := strconv.Atoi(value)
			if err == nil {
				resp.Status = statusCode
			}
		default:
			// Regular header
			headers[key] = value
		}
	}

	// Decide whether this is a request or response based on pseudo-headers
	if req.Method != "" && req.Path != "" {
		req.EndStream = strings.Contains(flagsLine, "END_STREAM")
		return req, nil
	}
	if resp.Status != 0 {
		resp.EndStream = strings.Contains(flagsLine, "END_STREAM")
		return resp, nil
	}

	return nil, errors.New("missing required HTTP/2 pseudo-headers")
}

// CreateUnparsedRecord creates a fallback record for unparsable frames
func CreateUnparsedRecord(frame RawFrame, errorType string, err error) *UnparsedRecord {
	// Estimate byte count from lines
	totalBytes := 0
	for _, line := range frame.Lines {
		totalBytes += len(line) + 1 // +1 for newline
	}

	// Create sample (first 200 chars, never full plaintext)
	sample := strings.Join(frame.Lines, "\n")
	if len(sample) > 200 {
		sample = sample[:200] + "..."
	}

	// Determine protocol guess
	protocol := "Unknown"
	switch DetectProtocol(frame) {
	case ProtocolHTTP1:
		protocol = "HTTP/1.1"
	case ProtocolHTTP2:
		protocol = "HTTP/2"
	}

	record := &UnparsedRecord{
		Bytes:     totalBytes,
		Protocol:  protocol,
		ErrorType: errorType,
		Timestamp: frame.Timestamp,
		RawSample: sample,
	}

	return record
}

// Helper: Truncate body if too large (prevent memory issues)
func truncateBody(body []byte, maxLen int) []byte {
	if len(body) > maxLen {
		return body[:maxLen]
	}
	return body
}

// deriveStreamID creates a deterministic UUID using a normalized connection token and, when present,
// an HTTP/2 stream identifier so requests and responses share the same key.
func deriveStreamID(frame RawFrame) uuid.UUID {
	connToken := normalizeConnToken(extractConnToken(frame))
	streamToken := extractStreamIdentifier(frame)

	switch {
	case connToken != "" && streamToken != "":
		return uuid.NewSHA1(uuid.NameSpaceOID, []byte(connToken+"|"+streamToken))
	case connToken != "":
		return uuid.NewSHA1(uuid.NameSpaceOID, []byte(connToken))
	case streamToken != "":
		return uuid.NewSHA1(uuid.NameSpaceOID, []byte(streamToken))
	}

	// Fallback to any UUID marker present.
	for _, line := range frame.Lines {
		if idx := strings.Index(line, "UUID:"); idx != -1 {
			rest := line[idx+5:]
			rest = strings.SplitN(rest, ",", 2)[0]
			rest = strings.Fields(rest)[0]
			return uuid.NewSHA1(uuid.NameSpaceOID, []byte(rest))
		}
	}
	return uuid.New()
}

// ParseHTTP2DataFrame parses HTTP/2 DATA frames
func ParseHTTP2DataFrame(frame RawFrame) (*ParsedDataFrame, error) {
	streamID := deriveStreamID(frame)

	// Find frame start
	startIdx := -1
	for i, l := range frame.Lines {
		if strings.Contains(strings.Join(strings.Fields(strings.TrimSpace(l)), " "), "Frame Type =>") {
			startIdx = i
			break
		}
	}
	if startIdx == -1 {
		return nil, errors.New("no frame marker found in DATA frame")
	}
	lines := frame.Lines[startIdx:]

	endStream := false
	isResp := isResponseFrame(frame)
	payloadLines := make([]string, 0, len(lines))

	for _, raw := range lines[1:] {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Flags") {
			if strings.Contains(line, "END_STREAM") {
				endStream = true
			}
			continue
		}
		if strings.HasPrefix(line, "Length") || strings.HasPrefix(line, "Padding Length") || strings.HasPrefix(line, "Stream Identifier") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "data") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				line = strings.TrimSpace(parts[1])
			} else {
				parts = strings.SplitN(line, "=>", 2)
				if len(parts) == 2 {
					line = strings.TrimSpace(parts[1])
				}
			}
		}
		if strings.HasPrefix(line, "Frame Type") {
			continue
		}
		payloadLines = append(payloadLines, line)
	}

	payload := []byte(strings.Join(payloadLines, "\n"))

	return &ParsedDataFrame{
		StreamID:   streamID,
		Payload:    payload,
		IsResponse: isResp,
		EndStream:  endStream,
		Timestamp:  frame.Timestamp,
	}, nil
}

func isResponseFrame(frame RawFrame) bool {
	for _, line := range frame.Lines {
		if strings.Contains(line, "HTTP2Response") || strings.Contains(line, "HTTP1Response") {
			return true
		}
	}
	// Heuristic: HTTP/1 metadata without method but with HTTP/1.x prefix
	if len(frame.Lines) > 0 {
		first := strings.TrimSpace(frame.Lines[0])
		if strings.HasPrefix(first, "HTTP/1.") {
			return true
		}
	}
	return false
}

func extractConnToken(frame RawFrame) string {
	for _, line := range frame.Lines {
		if idx := strings.Index(line, "UUID:"); idx != -1 {
			rest := line[idx+5:]
			rest = strings.SplitN(rest, ",", 2)[0]
			rest = strings.Fields(rest)[0]
			return rest
		}
	}
	return ""
}

func normalizeConnToken(token string) string {
	if token == "" {
		return ""
	}
	parts := strings.Split(token, "_")
	if len(parts) >= 4 {
		// e.g., 699846_699846_curl_2457943216_1_0.0.0.0 -> keep first 4 to drop direction suffixes.
		return strings.Join(parts[:4], "_")
	}
	return token
}

func extractStreamIdentifier(frame RawFrame) string {
	for _, line := range frame.Lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "stream identifier") {
			fields := strings.Fields(line)
			for _, f := range fields {
				f = strings.Trim(f, ":")
				if strings.HasPrefix(f, "0x") || isAllDigits(f) {
					if val, err := strconv.ParseInt(f, 0, 64); err == nil {
						return strconv.FormatInt(val, 10)
					}
				}
			}
		}
	}
	return ""
}

func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
