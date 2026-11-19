package pcap

import (
	"io"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/tags"
	"github.com/akitasoftware/go-utils/optionals"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/capturestats"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

const (
	// The same default as tcpdump (libpcap's MAXIMUM_SNAPLEN).
	//
	// Do not lower this to 64 KiB. Snaplen caps the whole captured frame,
	// including the link-layer header, so a max-size 65,535-byte IP packet is
	// a 65,549-byte frame. Such frames are common on lo (default MTU 64 KiB)
	// and with GSO/GRO, and truncating them leaves TCP reassembly gaps.
	defaultSnapLen = 262144
	pcapBufSize    = 32 * 1024 * 1024

	// The same as gopacket's PacketSource.Packets().
	packetChanSize = 1000

	// Not pcap.BlockForever: a blocking read holds the handle's lock until a
	// packet arrives, so Close hangs on an idle interface (a deleted pod's) and
	// leaks the socket, its ring and the pod's netns (INS-537).
	ReadTimeout = 100 * time.Millisecond
)

type pcapWrapper interface {
	capturePackets(done <-chan struct{}, interfaceName, bpfFilter string, targetNetworkNamespaceOpt optionals.Optional[string], stats *capturestats.Stats, telemetryCountReporter func(string, uint64)) (<-chan gopacket.Packet, error)
	getInterfaceAddrs(interfaceName string) ([]net.IP, error)
}

type pcapImpl struct {
	ServiceID akid.ServiceID
	TraceTags map[tags.Key]string
}

func (p *pcapImpl) capturePackets(done <-chan struct{}, interfaceName, bpfFilter string, targetNetworkNamespaceOpt optionals.Optional[string], stats *capturestats.Stats, telemetryCountReporter func(string, uint64)) (<-chan gopacket.Packet, error) {
	handle, err := GetPcapHandle(interfaceName, defaultSnapLen, true, ReadTimeout, optionals.Some[int32](pcapBufSize), targetNetworkNamespaceOpt)
	if err != nil {
		return nil, err
	}

	if bpfFilter != "" {
		if err := handle.SetBPFFilter(bpfFilter); err != nil {
			handle.Close()
			return nil, errors.Wrap(err, "failed to set BPF filter")
		}
	}

	// Creating the packet source takes some time - do it here so the caller can
	// be confident that pakcets are being watched after this function returns.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true

	// Watch libpcap's own capture counters, which tell us whether the kernel is
	// discarding packets before we ever see them. See capture_stats.go.
	statsDone := make(chan struct{})
	statsStopped := make(chan struct{})
	go func() {
		defer close(statsStopped)
		pollPcapStats(handle, interfaceName, stats, statsDone, telemetryCountReporter)
	}()

	// Read packets in our own loop rather than with packetSource.Packets(),
	// whose goroutine has no stop signal: it blocks on a full channel once the
	// consumer stops reading, and Close must wait for its read in progress.
	// Here one goroutine owns the handle and closes it only after its last read.
	pktChan := make(chan gopacket.Packet, packetChanSize)
	go func() {
		defer func() {
			// Wait for the stats poller to return before closing the handle:
			// pcap_stats dereferences the handle without locking, so a sample in
			// flight during Close is a use-after-free.
			close(statsDone)
			<-statsStopped

			// No read is in flight, so Close returns at once. Close the channel
			// after it, so a closed channel means the handle is released.
			handle.Close()
			close(pktChan)
		}()
		readPackets(done, packetSource, pktChan)
	}()
	return pktChan, nil
}

// readPackets sends the packets read from src to out until done is closed or
// the source ends. Reads return at least every ReadTimeout, so an idle
// interface still sees done promptly.
func readPackets(done <-chan struct{}, src *gopacket.PacketSource, out chan<- gopacket.Packet) {
	for {
		select {
		case <-done:
			return
		default:
		}

		pkt, err := src.NextPacket()
		switch {
		case err == nil:
			select {
			case out <- pkt:
			case <-done:
				return
			}
		case err == pcap.NextErrorTimeoutExpired:
			// No packets within ReadTimeout; check done and read again.
		case isUnrecoverableReadError(err):
			return
		case isTemporaryReadError(err):
			// Retry at once, as gopacket's own reader does.
		default:
			// Retry after a short pause, as gopacket's own reader does.
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// The errors on which gopacket's own reader stops, such as io.EOF once the
// handle is closed.
func isUnrecoverableReadError(err error) bool {
	return err == io.EOF || err == io.ErrUnexpectedEOF ||
		err == io.ErrNoProgress || err == io.ErrClosedPipe || err == io.ErrShortBuffer ||
		err == syscall.EBADF ||
		strings.Contains(err.Error(), "use of closed file")
}

// The errors on which gopacket's own reader retries at once.
func isTemporaryReadError(err error) bool {
	if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
		return true
	}
	return err == syscall.EAGAIN
}

func (p *pcapImpl) getInterfaceAddrs(interfaceName string) ([]net.IP, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, errors.Wrapf(err, "no network interface with name %s", interfaceName)
	}

	hostIPs := []net.IP{}
	if addrs, err := iface.Addrs(); err != nil {
		return nil, errors.Wrapf(err, "failed to get addresses on interface %s", iface.Name)
	} else {
		for _, addr := range addrs {
			if tcpAddr, ok := addr.(*net.TCPAddr); ok {
				hostIPs = append(hostIPs, tcpAddr.IP)
			} else if udpAddr, ok := addr.(*net.UDPAddr); ok {
				hostIPs = append(hostIPs, udpAddr.IP)
			} else if ipNet, ok := addr.(*net.IPNet); ok {
				// TODO: Remove assumption that the host IP is the first IP in the
				// network.
				ip := ipNet.IP.Mask(ipNet.Mask)
				nextIP(ip)
				hostIPs = append(hostIPs, ip)
			} else {
				printer.Warningf("Ignoring host address of unknown type: %v\n", addr)
			}
		}
	}
	return hostIPs, nil
}

func nextIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}
