package pcap

import (
	"net"

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
	BlockForever   = pcap.BlockForever
	pcapBufSize    = 32 * 1024 * 1024
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
	handle, err := GetPcapHandle(interfaceName, defaultSnapLen, true, BlockForever, optionals.Some[int32](pcapBufSize), targetNetworkNamespaceOpt)
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
	pktChan := packetSource.Packets()

	// Watch libpcap's own capture counters, which tell us whether the kernel is
	// discarding packets before we ever see them. See capture_stats.go.
	statsDone := make(chan struct{})
	statsStopped := make(chan struct{})
	go func() {
		defer close(statsStopped)
		pollPcapStats(handle, interfaceName, stats, statsDone, telemetryCountReporter)
	}()

	go func() {
		<-done

		// Wait for the stats poller to return before closing the handle:
		// pcap_stats dereferences the handle without locking, so a sample in
		// flight during Close is a use-after-free.
		close(statsDone)
		<-statsStopped

		handle.Close()
	}()
	return pktChan, nil
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
