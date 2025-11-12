package ebpf

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/tags"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
)

// NOTE: This implementation requires the cilium/ebpf package.
// To add it, run: go get github.com/cilium/ebpf
//
// The eBPF program must be compiled first:
//   clang -target bpf -O2 -g -c openssl_hook.c -o openssl_hook.o
//
// Then use bpf2go to generate Go bindings:
//   go generate ./ebpf

// SSL event structure matching the eBPF program
type SSLEvent struct {
	TimestampNS uint64
	PID         uint32
	TID         uint32
	FD          uint32
	IsWrite     uint32 // 1 for write (before encryption), 0 for read (after decryption)
	DataLen     uint32
	Data        [65536]byte
}

// HTTPSCapture manages eBPF-based HTTPS traffic capture
type HTTPSCapture struct {
	// NOTE: These types are from cilium/ebpf package
	// collection *ebpf.Collection
	// links      []link.Link
	// events     *perf.Reader
	stopChan chan struct{}
	
	// Connection tracking to associate SSL events with network connections
	connTracker *ConnectionTracker
	
	// Output channel for parsed network traffic
	outputChan chan<- akinet.ParsedNetworkTraffic
	
	serviceID akid.ServiceID
	traceTags map[tags.Key]string
	telemetry telemetry.Tracker
	
	// Flag to indicate if capture is active
	active bool
}

// ConnectionInfo tracks SSL connection metadata
type ConnectionInfo struct {
	PID      uint32
	TID      uint32
	FD       uint32
	LocalIP  string
	LocalPort uint16
	RemoteIP string
	RemotePort uint16
	StartTime time.Time
}

// ConnectionTracker maps SSL file descriptors to connection information
type ConnectionTracker struct {
	connections map[uint32]*ConnectionInfo
	// Map PID+FD to connection info for faster lookup
	pidFdMap map[string]*ConnectionInfo
}

func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		connections: make(map[uint32]*ConnectionInfo),
		pidFdMap:    make(map[string]*ConnectionInfo),
	}
}

// NewHTTPSCapture creates a new HTTPS capture instance
func NewHTTPSCapture(
	serviceID akid.ServiceID,
	traceTags map[tags.Key]string,
	outputChan chan<- akinet.ParsedNetworkTraffic,
	telemetry telemetry.Tracker,
) (*HTTPSCapture, error) {
	// NOTE: Actual implementation would:
	// 1. Remove memory limits: rlimit.RemoveMemlock()
	// 2. Load compiled eBPF program using bpf2go-generated bindings
	// 3. Open perf event reader
	
	// For now, return a placeholder that shows the structure
	printer.Debugf("HTTPS capture initialized (eBPF support requires cilium/ebpf package and compiled eBPF programs)\n")
	
	return &HTTPSCapture{
		stopChan:    make(chan struct{}),
		connTracker: NewConnectionTracker(),
		outputChan:  outputChan,
		serviceID:   serviceID,
		traceTags:   traceTags,
		telemetry:   telemetry,
		active:      false,
	}, nil
}

// AttachToProcess attaches eBPF uprobes to a specific process
// NOTE: This is a placeholder showing the structure. Actual implementation requires:
// 1. Compiled eBPF programs loaded via bpf2go
// 2. cilium/ebpf package for link management
func (h *HTTPSCapture) AttachToProcess(pid int, libPath string) error {
	// Actual implementation would:
	// 1. Open the executable/library: link.OpenExecutable(libPath)
	// 2. Attach uprobe to SSL_write: uprobe.Uprobe("SSL_write", program, nil)
	// 3. Attach uretprobe to SSL_read: uprobe.Uretprobe("SSL_read", program, nil)
	// 4. Store links for cleanup
	
	printer.Debugf("Would attach eBPF uprobes to PID %d, library %s\n", pid, libPath)
	return errors.New("eBPF uprobe attachment not yet implemented - requires cilium/ebpf package")
}

// Start begins capturing HTTPS traffic
func (h *HTTPSCapture) Start() error {
	if h.active {
		return errors.New("HTTPS capture already started")
	}
	
	// NOTE: Actual implementation would:
	// 1. Start processing events from perf ring buffer
	// 2. Handle uprobe events in a goroutine
	go h.processEvents()
	
	h.active = true
	printer.Debugf("HTTPS capture started (placeholder - eBPF not yet fully implemented)\n")
	return nil
}

// Stop stops capturing and cleans up resources
func (h *HTTPSCapture) Stop() error {
	if !h.active {
		return nil
	}
	
	close(h.stopChan)

	// NOTE: Actual implementation would:
	// 1. Close all eBPF links
	// 2. Close perf reader
	// 3. Close eBPF collection

	h.active = false
	printer.Debugf("HTTPS capture stopped\n")
	return nil
}

// processEvents reads events from the perf ring buffer and processes them
// NOTE: This is a placeholder. Actual implementation requires perf.Reader from cilium/ebpf
func (h *HTTPSCapture) processEvents() {
	// Actual implementation would:
	// 1. Read from perf.Reader in a loop
	// 2. Parse SSLEvent structures
	// 3. Call handleSSLEvent for each event
	
	<-h.stopChan
}

// handleSSLEvent processes a single SSL event and converts it to ParsedNetworkTraffic
func (h *HTTPSCapture) handleSSLEvent(event *SSLEvent) {
	// Get connection info
	connInfo := h.connTracker.GetConnection(event.PID, event.FD)
	if connInfo == nil {
		// Try to resolve connection info from /proc
		connInfo = h.resolveConnectionInfo(event.PID, event.FD)
		if connInfo != nil {
			h.connTracker.AddConnection(event.PID, event.FD, connInfo)
		}
	}

	// Extract the actual data (only up to DataLen bytes)
	data := event.Data[:event.DataLen]
	if len(data) == 0 {
		return
	}

	// Create ParsedNetworkTraffic
	var srcIP, dstIP string
	var srcPort, dstPort uint16

	if connInfo != nil {
		srcIP = connInfo.LocalIP
		srcPort = connInfo.LocalPort
		dstIP = connInfo.RemoteIP
		dstPort = connInfo.RemotePort
	} else {
		// Fallback: use placeholder values
		srcIP = "0.0.0.0"
		dstIP = "0.0.0.0"
	}

	timestamp := time.Unix(0, int64(event.TimestampNS))

	// Parse the plaintext data as HTTP
	parsedContent := h.parseHTTPFromPlaintext(data, event.IsWrite == 1)

	pnt := akinet.ParsedNetworkTraffic{
		SrcIP:           parseIP(srcIP),
		SrcPort:         int(srcPort),
		DstIP:           parseIP(dstIP),
		DstPort:         int(dstPort),
		ObservationTime: timestamp,
		FinalPacketTime: timestamp,
		Content:         parsedContent,
	}

	// Send to output channel
	select {
	case h.outputChan <- pnt:
	case <-h.stopChan:
		return
	}
}

// parseHTTPFromPlaintext attempts to parse plaintext data as HTTP
func (h *HTTPSCapture) parseHTTPFromPlaintext(data []byte, isWrite bool) akinet.ParsedNetworkContent {
	// NOTE: This is a simplified implementation. In production, you'd want to:
	// 1. Use the actual HTTP parser factories from akinet/http
	// 2. Handle partial HTTP messages
	// 3. Track state across multiple SSL_write/SSL_read calls
	// 4. Handle HTTP/2
	
	dataStr := string(data)
	
	// Try to detect HTTP request
	if strings.HasPrefix(dataStr, "GET ") || strings.HasPrefix(dataStr, "POST ") ||
		strings.HasPrefix(dataStr, "PUT ") || strings.HasPrefix(dataStr, "DELETE ") ||
		strings.HasPrefix(dataStr, "PATCH ") || strings.HasPrefix(dataStr, "HEAD ") ||
		strings.HasPrefix(dataStr, "OPTIONS ") {
		// This looks like an HTTP request
		return akinet.DroppedBytes(len(data)) // Placeholder - would use HTTP parser
	}
	
	// Try to detect HTTP response
	if strings.HasPrefix(dataStr, "HTTP/") {
		// This looks like an HTTP response
		return akinet.DroppedBytes(len(data)) // Placeholder - would use HTTP parser
	}
	
	// Not recognized as HTTP, return as dropped bytes
	return akinet.DroppedBytes(len(data))
}

// resolveConnectionInfo attempts to resolve connection info from /proc filesystem
func (h *HTTPSCapture) resolveConnectionInfo(pid uint32, fd uint32) *ConnectionInfo {
	// Read /proc/<pid>/fdinfo/<fd> to get socket inode
	fdinfoPath := fmt.Sprintf("/proc/%d/fdinfo/%d", pid, fd)
	data, err := os.ReadFile(fdinfoPath)
	if err != nil {
		return nil
	}

	// Parse socket inode from fdinfo
	// Format: "socket:[12345]"
	var inode uint64
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "socket:") {
			inodeStr := strings.TrimPrefix(line, "socket:[")
			inodeStr = strings.TrimSuffix(inodeStr, "]")
			var err error
			inode, err = strconv.ParseUint(inodeStr, 10, 64)
			if err != nil {
				return nil
			}
			break
		}
	}

	if inode == 0 {
		return nil
	}

	// Read /proc/<pid>/net/tcp to find connection info by inode
	netTCPPath := fmt.Sprintf("/proc/%d/net/tcp", pid)
	connInfo := h.parseNetTCP(netTCPPath, inode)
	if connInfo != nil {
		connInfo.PID = pid
		connInfo.FD = fd
	}

	return connInfo
}

// parseNetTCP parses /proc/<pid>/net/tcp to find connection info by inode
func (h *HTTPSCapture) parseNetTCP(netTCPPath string, inode uint64) *ConnectionInfo {
	file, err := os.Open(netTCPPath)
	if err != nil {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Skip header line
	if scanner.Scan() {
		_ = scanner.Text()
	}

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// Parse inode (last field)
		parsedInode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil || parsedInode != inode {
			continue
		}

		// Parse local and remote addresses
		// Format: "local_address:port remote_address:port"
		localAddr := fields[1]
		remoteAddr := fields[2]

		connInfo := &ConnectionInfo{
			StartTime: time.Now(),
		}

		// Parse local address (format: "0100007F:1F90" = 127.0.0.1:8080)
		if localIP, localPort := parseNetAddress(localAddr); localIP != "" {
			connInfo.LocalIP = localIP
			connInfo.LocalPort = localPort
		}

		// Parse remote address
		if remoteIP, remotePort := parseNetAddress(remoteAddr); remoteIP != "" {
			connInfo.RemoteIP = remoteIP
			connInfo.RemotePort = remotePort
		}

		return connInfo
	}

	return nil
}

// parseNetAddress parses an address from /proc/net/tcp format
// Format: "0100007F:1F90" = 127.0.0.1:8080 (little-endian hex)
func parseNetAddress(addr string) (string, uint16) {
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		return "", 0
	}

	// Parse IP (little-endian hex)
	ipHex := parts[0]
	if len(ipHex) != 8 {
		return "", 0
	}

	// Convert from little-endian hex to IP
	ipBytes := make([]byte, 4)
	for i := 0; i < 4; i++ {
		byteStr := ipHex[i*2 : (i+1)*2]
		val, err := strconv.ParseUint(byteStr, 16, 8)
		if err != nil {
			return "", 0
		}
		ipBytes[3-i] = byte(val) // Reverse for little-endian
	}

	ip := fmt.Sprintf("%d.%d.%d.%d", ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])

	// Parse port (hex)
	portHex := parts[1]
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", 0
	}

	return ip, uint16(port)
}

func (ct *ConnectionTracker) GetConnection(pid uint32, fd uint32) *ConnectionInfo {
	key := fmt.Sprintf("%d:%d", pid, fd)
	return ct.pidFdMap[key]
}

func (ct *ConnectionTracker) AddConnection(pid uint32, fd uint32, info *ConnectionInfo) {
	ct.connections[fd] = info
	key := fmt.Sprintf("%d:%d", pid, fd)
	ct.pidFdMap[key] = info
}

func parseIP(ipStr string) net.IP {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return net.IPv4(0, 0, 0, 0)
	}
	return ip
}

