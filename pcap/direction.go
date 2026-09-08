package pcap

import (
	"net"

	"github.com/akitasoftware/akita-libs/akinet"
)

// DirectionHint holds netns-wide locals used to classify pcap HTTP as inbound
// or outbound. ListenPorts are application listen ports (mesh ports excluded).
type DirectionHint struct {
	LocalIPs    map[string]struct{} // IP.String() keys
	ListenPorts map[uint16]struct{}
}

func NewDirectionHint(ips []net.IP, ports []uint16) *DirectionHint {
	if len(ips) == 0 && len(ports) == 0 {
		return nil
	}
	h := &DirectionHint{
		LocalIPs:    make(map[string]struct{}, len(ips)),
		ListenPorts: make(map[uint16]struct{}, len(ports)),
	}
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		h.LocalIPs[ip.String()] = struct{}{}
	}
	for _, p := range ports {
		h.ListenPorts[p] = struct{}{}
	}
	return h
}

func (h *DirectionHint) isLocal(ip net.IP) bool {
	if h == nil || ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	_, ok := h.LocalIPs[ip.String()]
	return ok
}

func (h *DirectionHint) isListenPort(port int) bool {
	if h == nil {
		return false
	}
	_, ok := h.ListenPorts[uint16(port)]
	return ok
}

func (h *DirectionHint) isEnvoyPort(port int) bool {
	return port >= 15000 && port <= 15090
}

// classifyHTTPDirection mirrors eBPF directionForPair using packet IPs/ports.
// Both-local (Istio REDIRECT on lo) uses listen/Envoy port tie-break.
func classifyHTTPDirection(content akinet.ParsedNetworkContent, srcIP, dstIP net.IP, srcPort, dstPort int, hint *DirectionHint) akinet.NetTrafficDirection {
	if hint == nil {
		return akinet.DirectionUnknown
	}
	srcLocal := hint.isLocal(srcIP)
	dstLocal := hint.isLocal(dstIP)

	switch content.(type) {
	case akinet.HTTPRequest:
		return classifyRequestDirection(srcLocal, dstLocal, dstPort, hint)
	case akinet.HTTPResponse:
		// Invert request rule using the response's src as the "server" side.
		return classifyRequestDirection(dstLocal, srcLocal, srcPort, hint)
	default:
		return akinet.DirectionUnknown
	}
}

func classifyRequestDirection(srcLocal, dstLocal bool, dstPort int, hint *DirectionHint) akinet.NetTrafficDirection {
	switch {
	case dstLocal && !srcLocal:
		return akinet.DirectionInbound
	case srcLocal && !dstLocal:
		return akinet.DirectionOutbound
	case srcLocal && dstLocal:
		// Mesh / loopback: prefer listen-port as inbound server, Envoy as outbound.
		if hint.isListenPort(dstPort) {
			return akinet.DirectionInbound
		}
		if hint.isEnvoyPort(dstPort) {
			return akinet.DirectionOutbound
		}
		// Ephemeral client → local peer without known listen port: outbound.
		return akinet.DirectionOutbound
	default:
		return akinet.DirectionUnknown
	}
}
