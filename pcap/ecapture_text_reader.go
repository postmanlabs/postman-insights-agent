package pcap

import (
	"bufio"
	"context"
	"io"
	"strings"
	"time"

	"github.com/postmanlabs/postman-insights-agent/printer"
)

// EcaptureTextReader reads eCapture text output from stdout and produces RawFrames
type EcaptureTextReader struct {
	reader       io.Reader
	frameChan    chan RawFrame
	errChan      chan error
	ctx          context.Context
	cancel       context.CancelFunc
	podName      string
	frameBuffer  []string // Accumulates lines for current frame
	lastUUIDLine string   // Most recent line containing UUID metadata
}

// NewEcaptureTextReader creates a reader for eCapture text mode output
func NewEcaptureTextReader(reader io.Reader, podName string) *EcaptureTextReader {
	ctx, cancel := context.WithCancel(context.Background())
	return &EcaptureTextReader{
		reader:      reader,
		frameChan:   make(chan RawFrame, 100), // Buffer to prevent blocking
		errChan:     make(chan error, 1),
		ctx:         ctx,
		cancel:      cancel,
		podName:     podName,
		frameBuffer: make([]string, 0, 50),
	}
}

// Start begins reading from stdout and sending frames to the channel
func (r *EcaptureTextReader) Start() {
	printer.Infof("🔥 DEBUG: Text reader started for pod %s\n", r.podName)
	go r.readLoop()
}

// FrameChannel returns the channel where parsed frames are sent
func (r *EcaptureTextReader) FrameChannel() <-chan RawFrame {
	return r.frameChan
}

// ErrorChannel returns the channel where errors are sent
func (r *EcaptureTextReader) ErrorChannel() <-chan error {
	return r.errChan
}

// Stop stops the reader and closes channels
func (r *EcaptureTextReader) Stop() {
	r.cancel()
}

// readLoop continuously reads from stdout and accumulates frames
func (r *EcaptureTextReader) readLoop() {
	defer close(r.frameChan)
	defer close(r.errChan)

	scanner := bufio.NewScanner(r.reader)
	// Increase buffer size to handle large frames (1MB max)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, len(buf))

	lastLineTime := time.Now()
	frameTimeout := 5 * time.Second

	// Goroutine to check for timeouts
	timeoutTicker := time.NewTicker(1 * time.Second)
	defer timeoutTicker.Stop()

	go func() {
		for {
			select {
			case <-r.ctx.Done():
				return
			case <-timeoutTicker.C:
				// Check if we have buffered lines that haven't been completed
				if len(r.frameBuffer) > 0 && time.Since(lastLineTime) > frameTimeout {
					printer.Debugf("Frame timeout for pod %s, flushing %d buffered lines\n",
						r.podName, len(r.frameBuffer))
					r.flushFrame("timeout")
				}
			}
		}
	}()

	linesRead := 0
	for scanner.Scan() {
		select {
		case <-r.ctx.Done():
			return
		default:
		}

		line := scanner.Text()
		lastLineTime = time.Now()
		linesRead++

		// Log first few lines to verify we're reading data
		if linesRead <= 10 {
			printer.Infof("🔥 DEBUG: Text reader line %d for pod %s: %s\n", linesRead, r.podName, line)
		} else if linesRead == 11 {
			printer.Infof("🔥 DEBUG: Text reader receiving data for pod %s (suppressing further line logs)\n", r.podName)
		}

		// Skip completely empty lines if buffer is empty
		if len(r.frameBuffer) == 0 && strings.TrimSpace(line) == "" {
			continue
		}

		// Check if this line starts a new frame
		if r.isFrameStart(line) {
			// Flush previous frame if any
			if len(r.frameBuffer) > 0 {
				r.flushFrame("")
			}
		}

		// Add line to buffer
		r.frameBuffer = append(r.frameBuffer, line)

		// Track UUID metadata for use when parsing frames
		if strings.Contains(line, "UUID:") {
			r.lastUUIDLine = line
		}

		// Check if this line ends the current frame
		if r.isFrameEnd(line) {
			r.flushFrame("")
		}
	}

	// Check for scanner errors
	if err := scanner.Err(); err != nil {
		printer.Errorf("Error reading eCapture output for pod %s: %v\n", r.podName, err)
		select {
		case r.errChan <- err:
		case <-r.ctx.Done():
		}
	}

	// Flush any remaining buffered lines
	if len(r.frameBuffer) > 0 {
		r.flushFrame("eof")
	}
}

// isFrameStart determines if a line marks the beginning of a new frame
func (r *EcaptureTextReader) isFrameStart(line string) bool {
	trimmed := strings.TrimSpace(line)

	// HTTP/2: "Frame Type => HEADERS" or "Frame Type\t=>\tHEADERS" (with tabs)
	// Normalize whitespace to handle both spaces and tabs
	normalizedLine := strings.Join(strings.Fields(trimmed), " ")
	if strings.HasPrefix(normalizedLine, "Frame Type =>") {
		return true
	}

	// HTTP/1.1 Request: HTTP method at start of line
	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"} {
		if strings.HasPrefix(trimmed, method+" ") {
			return true
		}
	}

	// HTTP/1.1 Response: "HTTP/1.x" at start
	if strings.HasPrefix(trimmed, "HTTP/1.") {
		return true
	}

	return false
}

// isFrameEnd determines if a line marks the end of the current frame
func (r *EcaptureTextReader) isFrameEnd(line string) bool {
	// Empty line typically marks end of headers in HTTP/1.1
	// For HTTP/2, we'll rely on detecting the next frame start
	trimmed := strings.TrimSpace(line)
	if trimmed == "" && len(r.frameBuffer) > 1 {
		// Only consider empty line as end if we have content
		return true
	}

	// For HTTP/2 DATA frames, we need to handle body content
	// This is a simple heuristic - in practice, may need refinement
	if len(r.frameBuffer) > 0 {
		firstLine := strings.TrimSpace(r.frameBuffer[0])
		if strings.Contains(firstLine, "Frame Type => DATA") {
			// DATA frames might have body content
			// For now, consider them complete after a few lines
			if len(r.frameBuffer) >= 10 {
				return true
			}
		}
	}

	return false
}

// flushFrame sends the accumulated buffer as a RawFrame
func (r *EcaptureTextReader) flushFrame(reason string) {
	if len(r.frameBuffer) == 0 {
		return
	}

	// If the buffer lacks UUID metadata but we have a recent UUID line, prepend it for downstream parsing.
	if !bufferHasUUID(r.frameBuffer) && r.lastUUIDLine != "" && bufferHasFrameType(r.frameBuffer) {
		r.frameBuffer = append([]string{r.lastUUIDLine}, r.frameBuffer...)
	}

	// Determine frame type from buffered lines
	frameType := r.detectFrameType(r.frameBuffer)

	frame := RawFrame{
		FrameType: frameType,
		Lines:     make([]string, len(r.frameBuffer)),
		Timestamp: time.Now(),
	}

	// Copy buffer to frame
	copy(frame.Lines, r.frameBuffer)

	// Send frame to channel (non-blocking with timeout)
	select {
	case r.frameChan <- frame:
		printer.Infof("🔥 DEBUG: Flushed %s frame for pod %s (%d lines)%s - FIRST LINE: %s\n",
			frameType, r.podName, len(frame.Lines),
			func() string {
				if reason != "" {
					return " [" + reason + "]"
				}
				return ""
			}(),
			func() string {
				if len(frame.Lines) > 0 {
					if len(frame.Lines[0]) > 100 {
						return frame.Lines[0][:100] + "..."
					}
					return frame.Lines[0]
				}
				return "(no lines)"
			}())
	case <-time.After(1 * time.Second):
		printer.Warningf("Frame channel blocked for pod %s, dropping frame\n", r.podName)
	case <-r.ctx.Done():
		return
	}

	// Clear buffer for next frame
	r.frameBuffer = r.frameBuffer[:0]
}

// detectFrameType examines the first line to determine frame type
func (r *EcaptureTextReader) detectFrameType(lines []string) string {
	if len(lines) == 0 {
		return "UNKNOWN"
	}

	// Scan for explicit frame type markers anywhere in the buffer.
	for _, l := range lines {
		normalizedLine := strings.Join(strings.Fields(strings.TrimSpace(l)), " ")
		if strings.HasPrefix(normalizedLine, "Frame Type =>") {
			parts := strings.SplitN(normalizedLine, "=>", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
			return "HTTP2_UNKNOWN"
		}
	}

	trimmed := strings.TrimSpace(lines[0])

	// HTTP/1.1 request
	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"} {
		if strings.HasPrefix(trimmed, method+" ") {
			return "HTTP1_REQUEST"
		}
	}

	// HTTP/1.1 response
	if strings.HasPrefix(trimmed, "HTTP/1.") {
		return "HTTP1_RESPONSE"
	}

	return "UNKNOWN"
}

func bufferHasUUID(lines []string) bool {
	for _, l := range lines {
		if strings.Contains(l, "UUID:") {
			return true
		}
	}
	return false
}

func bufferHasFrameType(lines []string) bool {
	for _, l := range lines {
		normalized := strings.Join(strings.Fields(strings.TrimSpace(l)), " ")
		if strings.HasPrefix(normalized, "Frame Type =>") {
			return true
		}
	}
	return false
}
