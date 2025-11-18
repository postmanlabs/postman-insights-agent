package https

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/memview"
	"github.com/google/uuid"

	"github.com/postmanlabs/postman-insights-agent/ebpf/openssl"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/trace"
)

// Collector bridges decrypted TLS payloads into the Akita trace pipeline.
type Collector struct {
	probe      *openssl.Probe
	resolver   *socketResolver
	downstream trace.Collector

	conns map[uint64]*connState
	mu    sync.Mutex

	cancel context.CancelFunc
}

// Config configures the HTTPS collector.
type Config struct {
	Context   context.Context
	Libraries []string
	Collector trace.Collector
}

func StartCollector(cfg Config) (*Collector, error) {
	if cfg.Context == nil {
		cfg.Context = context.Background()
	}
	if cfg.Collector == nil {
		return nil, fmt.Errorf("https collector: downstream collector required")
	}
	probe, err := openssl.NewProbe(cfg.Context, openssl.Options{Libraries: cfg.Libraries})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(cfg.Context)
	c := &Collector{
		probe:      probe,
		resolver:   newSocketResolver(2 * time.Second),
		downstream: cfg.Collector,
		conns:      make(map[uint64]*connState),
		cancel:     cancel,
	}
	go c.run(ctx)
	return c, nil
}

// Close stops the probe and releases all state.
func (c *Collector) Close() {
	c.cancel()
	c.probe.Close()
}

func (c *Collector) run(ctx context.Context) {
	cleanup := time.NewTicker(30 * time.Second)
	defer cleanup.Stop()
	for {
		select {
		case evt, ok := <-c.probe.Events():
			if !ok {
				return
			}
			c.handleEvent(evt)
		case err := <-c.probe.Errors():
			printer.Debugf("openssl probe error: %v\n", err)
		case <-cleanup.C:
			c.cleanupIdle()
		case <-ctx.Done():
			return
		}
	}
}

func (c *Collector) handleEvent(evt openssl.Event) {
	info, err := c.resolver.Resolve(evt.PID, evt.FD)
	if err != nil {
		printer.Debugf("openssl resolver error: %v\n", err)
		return
	}
	c.mu.Lock()
	conn := c.conns[evt.SSLPtr]
	if conn == nil {
		conn = newConnState(evt.SSLPtr, info)
		c.conns[evt.SSLPtr] = conn
	}
	conn.lastSeen = evt.Timestamp
	conn.info = info

	var outputs []akinet.ParsedNetworkTraffic
	switch evt.Direction {
	case openssl.DirectionClient:
		conn.requestBuf = append(conn.requestBuf, evt.Payload...)
		outputs = c.consumeRequests(conn, evt.Timestamp)
	case openssl.DirectionServer:
		conn.responseBuf = append(conn.responseBuf, evt.Payload...)
		outputs = c.consumeResponses(conn, evt.Timestamp)
	default:
		printer.Debugf("openssl: unknown direction %d\n", evt.Direction)
	}
	c.mu.Unlock()

	for _, pkt := range outputs {
		if err := c.downstream.Process(pkt); err != nil {
			printer.Debugf("openssl collector downstream error: %v\n", err)
		}
		pkt.Content.ReleaseBuffers()
	}
}

func (c *Collector) consumeRequests(conn *connState, ts time.Time) []akinet.ParsedNetworkTraffic {
	var out []akinet.ParsedNetworkTraffic
	for len(conn.requestBuf) > 0 {
		result, needMore, err := parseRequest(conn.requestBuf)
		if err != nil {
			printer.Debugf("openssl: request parse error: %v\n", err)
			conn.requestBuf = nil
			break
		}
		if needMore || result == nil {
			break
		}
		conn.requestBuf = conn.requestBuf[result.consumed:]
		pkt, err := buildHTTPRequest(conn, result.request, result.body, ts)
		if err != nil {
			printer.Debugf("openssl: build HTTP request error: %v\n", err)
			continue
		}
		out = append(out, pkt)
	}
	return out
}

func (c *Collector) consumeResponses(conn *connState, ts time.Time) []akinet.ParsedNetworkTraffic {
	var out []akinet.ParsedNetworkTraffic
	for len(conn.responseBuf) > 0 {
		result, needMore, err := parseResponse(conn.responseBuf)
		if err != nil {
			printer.Debugf("openssl: response parse error: %v\n", err)
			conn.responseBuf = nil
			break
		}
		if needMore || result == nil {
			break
		}
		conn.responseBuf = conn.responseBuf[result.consumed:]
		pkt, err := buildHTTPResponse(conn, result.response, result.body, ts)
		if err != nil {
			printer.Debugf("openssl: build HTTP response error: %v\n", err)
			continue
		}
		out = append(out, pkt)
	}
	return out
}

func (c *Collector) cleanupIdle() {
	cutoff := time.Now().Add(-2 * time.Minute)
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, conn := range c.conns {
		if conn.lastSeen.Before(cutoff) {
			delete(c.conns, key)
		}
	}
}

type connState struct {
	sslPtr      uint64
	info        socketInfo
	streamID    uuid.UUID
	nextSeq     int
	pendingSeqs []int

	requestBuf  []byte
	responseBuf []byte
	lastSeen    time.Time
}

func newConnState(ptr uint64, info socketInfo) *connState {
	return &connState{
		sslPtr:     ptr,
		info:       info,
		streamID:   uuid.New(),
		nextSeq:    1,
		lastSeen:   time.Now(),
	}
}

func buildHTTPRequest(conn *connState, req *http.Request, body []byte, ts time.Time) (akinet.ParsedNetworkTraffic, error) {
	host := req.Host
	if host == "" {
		host = req.Header.Get("Host")
	}
	if req.URL != nil && req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}
	seq := conn.nextSeq
	conn.nextSeq++
	conn.pendingSeqs = append(conn.pendingSeqs, seq)

	mv := memview.Empty()
	if len(body) > 0 {
		mv = memview.New(append([]byte(nil), body...))
	}

	akReq := akinet.HTTPRequest{
		StreamID:   conn.streamID,
		Seq:        seq,
		Method:     req.Method,
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		URL:        req.URL,
		Host:       host,
		Header:     req.Header.Clone(),
		Body:       mv,
		Cookies:    req.Cookies(),
	}

	pkt := akinet.ParsedNetworkTraffic{
		SrcIP:           copyIP(conn.info.localIP),
		SrcPort:         conn.info.localPort,
		DstIP:           copyIP(conn.info.remoteIP),
		DstPort:         conn.info.remotePort,
		Content:         akReq,
		ObservationTime: ts,
		FinalPacketTime: ts,
	}
	return pkt, nil
}

func buildHTTPResponse(conn *connState, resp *http.Response, body []byte, ts time.Time) (akinet.ParsedNetworkTraffic, error) {
	seq := 0
	if len(conn.pendingSeqs) > 0 {
		seq = conn.pendingSeqs[0]
		conn.pendingSeqs = conn.pendingSeqs[1:]
	} else {
		seq = conn.nextSeq
		conn.nextSeq++
	}
	mv := memview.Empty()
	if len(body) > 0 {
		mv = memview.New(append([]byte(nil), body...))
	}
	akResp := akinet.HTTPResponse{
		StreamID:   conn.streamID,
		Seq:        seq,
		StatusCode: resp.StatusCode,
		ProtoMajor: resp.ProtoMajor,
		ProtoMinor: resp.ProtoMinor,
		Header:     resp.Header.Clone(),
		Body:       mv,
	}
	pkt := akinet.ParsedNetworkTraffic{
		SrcIP:           copyIP(conn.info.remoteIP),
		SrcPort:         conn.info.remotePort,
		DstIP:           copyIP(conn.info.localIP),
		DstPort:         conn.info.localPort,
		Content:         akResp,
		ObservationTime: ts,
		FinalPacketTime: ts,
	}
	return pkt, nil
}

func copyIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}
