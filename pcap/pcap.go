package pcap

import (
	"net"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/tags"
	"github.com/akitasoftware/go-utils/optionals"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

const (
	// The same default as tcpdump.
	defaultSnapLen = 262144
	BlockForever   = pcap.BlockForever
)

type pcapWrapper interface {
	capturePackets(done <-chan struct{}, interfaceName, bpfFilter string, targetNetworkNamespaceOpt optionals.Optional[string]) (<-chan gopacket.Packet, error)
	getInterfaceAddrs(interfaceName string) ([]net.IP, error)
}

type pcapImpl struct {
	ServiceID akid.ServiceID
	TraceTags map[tags.Key]string
}

func (p *pcapImpl) capturePackets(done <-chan struct{}, interfaceName, bpfFilter string, targetNetworkNamespaceOpt optionals.Optional[string]) (<-chan gopacket.Packet, error) {
	handle, err := GetPcapHandle(interfaceName, defaultSnapLen, true, BlockForever, targetNetworkNamespaceOpt)
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
	pktChan := packetSource.Packets()

	// TODO: tune the packet channel buffer
	wrappedChan := make(chan gopacket.Packet, 10)
	go func() {
		// Closing the handle can take a long time, so we close wrappedChan first to
		// allow the packet consumer to advance with its processing logic while we
		// wait for the handle to close in this goroutine.
		defer func() {
			close(wrappedChan)
			handle.Close()
		}()

		startTime := time.Now()
		firstPacket := true
		bufferTimeSum := 0 * time.Second
		intervalLength := 1 * time.Minute
		for {
			select {
			case <-done:
				return
			case pkt, ok := <-pktChan:
				if ok {
					now := time.Now()
					if now.Sub(startTime) >= intervalLength {
						bufferLength := float64(bufferTimeSum.Nanoseconds()) / float64(intervalLength.Nanoseconds())
						podName, ok := p.TraceTags[tags.XAkitaKubernetesPod]
						if !ok {
							podName = "unknown"
						}
						printer.Debugf("Approximate captured-packets buffer length: %v, for svc %v and pod: %v\n", bufferLength, p.ServiceID, podName)
						bufferTimeSum = 0 * time.Second
						startTime = now
					}
					bufferTimeSum += now.Sub(pkt.Metadata().Timestamp)

					wrappedChan <- pkt

					if firstPacket {
						firstPacket = false
						ttfp := time.Since(startTime)
						printer.Debugf("Time to first packet on %s: %s\n", interfaceName, ttfp)
					}

				} else {
					return
				}
			}
		}
	}()
	return wrappedChan, nil
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
