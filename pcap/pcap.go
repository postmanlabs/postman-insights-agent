package pcap

import (
	"net"

	"github.com/akitasoftware/go-utils/optionals"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

const (
	// The same default as tcpdump.
	defaultSnapLen = 262144
)

type pcapWrapper interface {
	capturePackets(done <-chan struct{}, interfaceName, bpfFilter string, targetNetworkNamespaceOpt optionals.Optional[string]) (<-chan gopacket.Packet, error)
	getInterfaceAddrs(interfaceName string) ([]net.IP, error)
}

type pcapImpl struct{}

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
