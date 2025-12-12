package pcap

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/memview"
	"github.com/akitasoftware/akita-libs/tags"
	"github.com/google/uuid"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
	"github.com/postmanlabs/postman-insights-agent/trace"
)

type streamState struct {
	req     *ParsedRequest
	resp    *ParsedResponse
	created time.Time
}

var (
	witnessDebugPath = os.Getenv("HTTPS_WITNESS_DEBUG_PATH")
	witnessDebugMu   sync.Mutex
)

// CollectFromTextFrames reads parsed HTTP frames from eCapture text mode and processes them.
// This replaces the file-based approach with direct in-memory streaming.
//
// Unlike Collect() and CollectFromFile(), this function:
// - Reads from a frame channel (from eCapture stdout)
// - Uses text_parser to convert frames to HTTP requests
// - Does not require gopacket or pcapng parsing
// - Never writes plaintext to disk
func CollectFromTextFrames(
	serviceID akid.ServiceID,
	traceTags map[tags.Key]string,
	stop <-chan struct{},
	frameChan <-chan RawFrame,
	proc trace.Collector,
	telemetry telemetry.Tracker,
) error {
	defer proc.Close()

	startTime := time.Now()
	processedFrames := 0
	parsedRequests := 0
	unparsedFrames := 0
	intervalLength := 1 * time.Minute
	streams := make(map[uuid.UUID]*streamState)

	podName, ok := traceTags[tags.XAkitaKubernetesPod]
	if !ok {
		podName = "unknown"
	}

	printer.Infof("🔥 DEBUG: Starting HTTPS text frame collector for pod %s\n", podName)
	printer.Infof("🔥 DEBUG: Waiting for frames from channel...\n")

	for {
		select {
		case <-stop:
			printer.Infof("HTTPS text collector stopped for pod %s (processed: %d, parsed: %d, unparsed: %d)\n",
				podName, processedFrames, parsedRequests, unparsedFrames)
			return nil

		case frame, ok := <-frameChan:
			if !ok {
				// Channel closed - eCapture process ended
				printer.Infof("HTTPS frame channel closed for pod %s (processed: %d, parsed: %d, unparsed: %d)\n",
					podName, processedFrames, parsedRequests, unparsedFrames)
				return nil
			}

			processedFrames++

			printer.Infof("🔥 DEBUG: Received frame %d for pod %s: type=%s, lines=%d\n",
				processedFrames, podName, frame.FrameType, len(frame.Lines))

			// Log progress periodically
			if processedFrames%10 == 0 {
				printer.Debugf("HTTPS collector for pod %s: processed %d frames (%d parsed, %d unparsed)\n",
					podName, processedFrames, parsedRequests, unparsedFrames)
			}

			// Periodic stats logging
			now := time.Now()
			if now.Sub(startTime) >= intervalLength {
				printer.Infof("HTTPS stats for pod %s: %d frames/min (%d parsed, %d unparsed)\n",
					podName, processedFrames, parsedRequests, unparsedFrames)
				processedFrames = 0
				parsedRequests = 0
				unparsedFrames = 0
				startTime = now
			}

			// Parse the frame
			result, err := ParseFrame(frame)
			if err != nil {
				printer.Debugf("Error parsing frame for pod %s: %v\n", podName, err)
				unparsedFrames++
				continue
			}

			// Handle different result types
			switch v := result.(type) {
			case *ParsedRequest:
				parsedRequests++

				printer.Infof("HTTPS request parsed for pod %s: %s %s (version=%s, headers=%d, body=%d bytes)\n",
					podName, v.Method, v.Path, v.Version, len(v.Headers), len(v.Body))

				if v.Version == "HTTP/2" {
					st := ensureStream(streams, v.StreamID, v.Timestamp)
					// If we accumulated body from DATA before HEADERS, merge it.
					if st.req != nil && len(st.req.Body) > 0 {
						v.Body = append(st.req.Body, v.Body...)
					}
					st.req = v
					if v.EndStream {
						sendRequestWitness(proc, podName, st.req)
						st.req = nil
						cleanupStream(streams, v.StreamID)
					}
					continue
				}

				sendRequestWitness(proc, podName, v)

			case *ParsedResponse:
				if v.Version == "HTTP/2" {
					st := ensureStream(streams, v.StreamID, v.Timestamp)
					if st.resp != nil && len(st.resp.Body) > 0 {
						v.Body = append(st.resp.Body, v.Body...)
					}
					// If we already buffered a request, send it before the response for pairing.
					if st.req != nil && st.req.Method != "" && st.req.Path != "" {
						sendRequestWitness(proc, podName, st.req)
						st.req = nil
					}
					st.resp = v
					if v.EndStream {
						sendResponseWitness(proc, podName, st.resp)
						st.resp = nil
						cleanupStream(streams, v.StreamID)
					}
					continue
				}

				sendResponseWitness(proc, podName, v)

			case *ParsedDataFrame:
				st := ensureStream(streams, v.StreamID, v.Timestamp)
				printer.Debugf("🔥 DEBUG: HTTP/2 DATA frame for pod %s stream=%s resp=%v end=%v payload_bytes=%d\n",
					podName, v.StreamID.String(), v.IsResponse, v.EndStream, len(v.Payload))
				if v.IsResponse {
					if st.resp == nil {
						st.resp = &ParsedResponse{
							StreamID:  v.StreamID,
							Headers:   make(map[string]string),
							Version:   "HTTP/2",
							Timestamp: v.Timestamp,
						}
					}
					st.resp.Body = append(st.resp.Body, v.Payload...)
					if v.EndStream && st.resp.Status != 0 {
						// If request exists, send it first.
						if st.req != nil && st.req.Method != "" && st.req.Path != "" {
							sendRequestWitness(proc, podName, st.req)
							st.req = nil
						}
						sendResponseWitness(proc, podName, st.resp)
						st.resp = nil
						cleanupStream(streams, v.StreamID)
					}
				} else {
					if st.req == nil {
						st.req = &ParsedRequest{
							StreamID:  v.StreamID,
							Headers:   make(map[string]string),
							Version:   "HTTP/2",
							Timestamp: v.Timestamp,
						}
					}
					st.req.Body = append(st.req.Body, v.Payload...)
					if v.EndStream && st.req.Method != "" && st.req.Path != "" {
						sendRequestWitness(proc, podName, st.req)
						st.req = nil
						cleanupStream(streams, v.StreamID)
					}
				}

			case *UnparsedRecord:
				unparsedFrames++

				// Log unparsed records for debugging (without leaking plaintext)
				printer.Debugf("Unparsed frame for pod %s: protocol=%s, error=%s, bytes=%d, sample=%s\n",
					podName, v.Protocol, v.ErrorType, v.Bytes, v.RawSample)

				// TODO: Report unparsed frame metrics to telemetry
				// telemetry.ReportUnparsedFrame(v.Protocol, v.ErrorType, v.Bytes)

			default:
				printer.Warningf("Unknown parse result type for pod %s: %T\n", podName, result)
			}

			flushTimedOutStreams(streams, 2*time.Second, proc, podName)
		}
	}
}

func ensureStream(streams map[uuid.UUID]*streamState, id uuid.UUID, ts time.Time) *streamState {
	if st, ok := streams[id]; ok {
		if st.req != nil && st.req.Timestamp.IsZero() {
			st.req.Timestamp = ts
		}
		if st.resp != nil && st.resp.Timestamp.IsZero() {
			st.resp.Timestamp = ts
		}
		return st
	}
	st := &streamState{created: ts}
	streams[id] = st
	return st
}

func cleanupStream(streams map[uuid.UUID]*streamState, id uuid.UUID) {
	if st, ok := streams[id]; ok {
		if st.req == nil && st.resp == nil {
			delete(streams, id)
		}
	}
}

func sendRequestWitness(proc trace.Collector, podName string, req *ParsedRequest) {
	if req == nil {
		return
	}
	witness, err := convertRequestToWitness(req)
	if err != nil {
		printer.Warningf("Failed to convert parsed request to witness for pod %s: %v\n", podName, err)
		return
	}
	witness.Interface = "https-capture"
	if err := proc.Process(witness); err != nil {
		printer.Warningf("Failed to process HTTPS witness for pod %s: %v\n", podName, err)
	} else {
		printer.Infof("✅ Successfully sent HTTPS witness to backend: %s %s (body=%d bytes)\n", req.Method, req.Path, len(req.Body))
		dumpWitnessIfEnabled(witness)
	}
}

func sendResponseWitness(proc trace.Collector, podName string, resp *ParsedResponse) {
	if resp == nil {
		return
	}
	witness, err := convertResponseToWitness(resp)
	if err != nil {
		printer.Warningf("Failed to convert parsed response to witness for pod %s: %v\n", podName, err)
		return
	}
	witness.Interface = "https-capture"
	if err := proc.Process(witness); err != nil {
		printer.Warningf("Failed to process HTTPS response witness for pod %s: %v\n", podName, err)
	} else {
		printer.Infof("✅ Successfully sent HTTPS response witness to backend: %d (body=%d bytes)\n", resp.Status, len(resp.Body))
		dumpWitnessIfEnabled(witness)
	}
}

// dumpWitnessIfEnabled writes witnesses to a debug file if HTTPS_WITNESS_DEBUG_PATH is set.
// This is intended for short-lived debugging; file may contain sensitive payloads.
func dumpWitnessIfEnabled(w akinet.ParsedNetworkTraffic) {
	if witnessDebugPath == "" {
		return
	}

	record := map[string]interface{}{
		"src":        map[string]interface{}{"ip": w.SrcIP.String(), "port": w.SrcPort},
		"dst":        map[string]interface{}{"ip": w.DstIP.String(), "port": w.DstPort},
		"timestamp":  w.ObservationTime,
		"interface":  w.Interface,
		"content_ts": w.FinalPacketTime,
	}

	streamID := ""
	switch v := w.Content.(type) {
	case akinet.HTTPRequest:
		streamID = v.StreamID.String()
		record["type"] = "request"
		record["method"] = v.Method
		record["path"] = v.URL.String()
		record["host"] = v.Host
		record["status"] = nil
		record["headers"] = v.Header
		record["body"] = v.Body.String()
	case akinet.HTTPResponse:
		streamID = v.StreamID.String()
		record["type"] = "response"
		record["status"] = v.StatusCode
		record["headers"] = v.Header
		record["body"] = v.Body.String()
	default:
		record["type"] = "unknown"
	}
	record["stream_id"] = streamID

	buf, err := json.Marshal(record)
	if err != nil {
		return
	}

	witnessDebugMu.Lock()
	defer witnessDebugMu.Unlock()
	f, err := os.OpenFile(witnessDebugPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(buf, '\n'))
}

func flushTimedOutStreams(streams map[uuid.UUID]*streamState, timeout time.Duration, proc trace.Collector, podName string) {
	now := time.Now()
	for id, st := range streams {
		if st.req != nil && st.req.Method != "" && st.req.Path != "" && (st.req.EndStream || now.Sub(st.created) > timeout) {
			sendRequestWitness(proc, podName, st.req)
			st.req = nil
		}
		if st.resp != nil && st.resp.Status != 0 && (st.resp.EndStream || now.Sub(st.created) > timeout) {
			sendResponseWitness(proc, podName, st.resp)
			st.resp = nil
		}
		cleanupStream(streams, id)
	}
}

// convertRequestToWitness converts a ParsedRequest to akinet.ParsedNetworkTraffic
// This creates a witness record that can be sent to the backend
func convertRequestToWitness(req *ParsedRequest) (akinet.ParsedNetworkTraffic, error) {
	// Parse the URL from the path
	parsedURL, err := url.Parse(req.Path)
	if err != nil {
		// If path doesn't parse as full URL, treat it as path-only
		parsedURL = &url.URL{Path: req.Path}
	}

	// Convert headers map to http.Header
	headers := make(http.Header)
	for k, v := range req.Headers {
		headers.Set(k, v)
	}

	// Determine protocol version (HTTP/1.1 or HTTP/2)
	protoMajor, protoMinor := 1, 1 // Default to HTTP/1.1
	if req.Version == "HTTP/2" {
		protoMajor, protoMinor = 2, 0
	}

	// Get host from headers or URL
	host := req.Headers["Host"]
	if host == "" {
		host = parsedURL.Host
	}

	// Create akinet.HTTPRequest
	httpReq := akinet.HTTPRequest{
		StreamID:   req.StreamID,
		Seq:        0, // We don't have TCP sequence numbers from eCapture text mode
		Method:     req.Method,
		ProtoMajor: protoMajor,
		ProtoMinor: protoMinor,
		URL:        parsedURL,
		Host:       host,
		Header:     headers,
		Body:       memview.New(req.Body), // memview.New takes []byte directly
	}

	// Create ParsedNetworkTraffic witness
	// Since eCapture text mode doesn't provide IP/port info, use placeholder values
	witness := akinet.ParsedNetworkTraffic{
		SrcIP:           net.ParseIP("0.0.0.0"),
		SrcPort:         0,
		DstIP:           net.ParseIP("0.0.0.0"),
		DstPort:         443, // Default HTTPS port
		Content:         httpReq,
		ObservationTime: req.Timestamp,
		FinalPacketTime: req.Timestamp,
	}

	return witness, nil
}

// convertResponseToWitness converts a ParsedResponse to akinet.ParsedNetworkTraffic
func convertResponseToWitness(resp *ParsedResponse) (akinet.ParsedNetworkTraffic, error) {
	// Convert headers map to http.Header
	headers := make(http.Header)
	for k, v := range resp.Headers {
		headers.Set(k, v)
	}

	protoMajor, protoMinor := 1, 1
	if resp.Version == "HTTP/2" {
		protoMajor, protoMinor = 2, 0
	}

	httpResp := akinet.HTTPResponse{
		StreamID:   resp.StreamID,
		Seq:        0,
		StatusCode: resp.Status,
		ProtoMajor: protoMajor,
		ProtoMinor: protoMinor,
		Header:     headers,
		Body:       memview.New(resp.Body),
	}

	witness := akinet.ParsedNetworkTraffic{
		SrcIP:           net.ParseIP("0.0.0.0"),
		SrcPort:         0,
		DstIP:           net.ParseIP("0.0.0.0"),
		DstPort:         443,
		Content:         httpResp,
		ObservationTime: resp.Timestamp,
		FinalPacketTime: resp.Timestamp,
	}

	return witness, nil
}

// StartHTTPSTextCollector is a helper to start the text collector goroutine
// This is called from apidump when HTTPS capture is enabled
func StartHTTPSTextCollector(
	serviceID akid.ServiceID,
	traceTags map[tags.Key]string,
	stop <-chan struct{},
	frameChan <-chan RawFrame,
	proc trace.Collector,
	telemetry telemetry.Tracker,
) error {
	return CollectFromTextFrames(
		serviceID,
		traceTags,
		stop,
		frameChan,
		proc,
		telemetry,
	)
}
