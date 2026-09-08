package apidump

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/akitasoftware/go-utils/optionals"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// TCP state LISTEN in /proc/net/tcp{,6}.
const tcpListenState = "0A"

// Default ports excluded from auto inbound capture (mesh sidecars, admin).
// Apps that listen only on these ports will not get an auto filter applied
// for those ports; other listen ports in the same netns still apply.
var defaultExcludedListenPorts = map[uint16]struct{}{
	22: {}, // ssh
}

// InboundEndpoints are local addresses and listen ports discovered in a
// capture network namespace for building an inbound-only BPF filter.
type InboundEndpoints struct {
	LocalIPs    []net.IP
	ListenPorts []uint16
}

func discoverInboundEndpointsInCurrentNS() (InboundEndpoints, error) {
	ips, err := listLocalIPs()
	if err != nil {
		return InboundEndpoints{}, err
	}
	ports, err := listListenPorts(defaultExcludedListenPorts)
	if err != nil {
		return InboundEndpoints{}, err
	}
	return InboundEndpoints{LocalIPs: ips, ListenPorts: ports}, nil
}

func listLocalIPs() ([]net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, errors.Wrap(err, "list interfaces")
	}
	seen := map[string]struct{}{}
	var ips []net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			printer.Warningf("Skipping interface %s while discovering local IPs: %v\n", iface.Name, err)
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch a := addr.(type) {
			case *net.IPNet:
				ip = a.IP
			case *net.IPAddr:
				ip = a.IP
			}
			if ip == nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			key := ip.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			ips = append(ips, append(net.IP(nil), ip...))
		}
	}
	return ips, nil
}

func listListenPorts(exclude map[uint16]struct{}) ([]uint16, error) {
	seen := map[uint16]struct{}{}
	var ports []uint16
	for _, name := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(name)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, errors.Wrapf(err, "open %s", name)
		}
		sc := bufio.NewScanner(f)
		first := true
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if first {
				first = false
				continue // header
			}
			if line == "" {
				continue
			}
			port, ok := parseListenPortFromProcNetTCPLine(line)
			if !ok {
				continue
			}
			if shouldExcludeListenPort(port, exclude) {
				continue
			}
			if _, ok := seen[port]; ok {
				continue
			}
			seen[port] = struct{}{}
			ports = append(ports, port)
		}
		err = sc.Err()
		_ = f.Close()
		if err != nil {
			return nil, errors.Wrapf(err, "scan %s", name)
		}
	}
	return ports, nil
}

func shouldExcludeListenPort(port uint16, exclude map[uint16]struct{}) bool {
	if _, ok := exclude[port]; ok {
		return true
	}
	// Istio / Envoy sidecar control and data ports.
	if port >= 15000 && port <= 15090 {
		return true
	}
	return false
}

// parseListenPortFromProcNetTCPLine returns the local port when the row is in
// LISTEN state. Format: sl local_address rem_address st ...
func parseListenPortFromProcNetTCPLine(line string) (uint16, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return 0, false
	}
	if fields[3] != tcpListenState {
		return 0, false
	}
	local := fields[1]
	colon := strings.LastIndexByte(local, ':')
	if colon < 0 || colon+1 >= len(local) {
		return 0, false
	}
	port64, err := strconv.ParseUint(local[colon+1:], 16, 16)
	if err != nil || port64 == 0 {
		return 0, false
	}
	return uint16(port64), true
}

// buildInboundBPFFilterForEndpoints builds a cBPF expression that keeps only
// traffic to/from the given local IPs on the given listen ports (same shape as
// getInboundBPFFilter's --port mode, but multi-port).
func buildInboundBPFFilterForEndpoints(ips []net.IP, ports []uint16) string {
	if len(ips) == 0 || len(ports) == 0 {
		return ""
	}
	var parts []string
	for _, ip := range ips {
		ipStr := ip.String()
		for _, port := range ports {
			p := strconv.FormatUint(uint64(port), 10)
			parts = append(parts,
				fmt.Sprintf("(src host %s and src port %s)", ipStr, p),
				fmt.Sprintf("(dst host %s and dst port %s)", ipStr, p),
			)
		}
	}
	return strings.Join(parts, " or ")
}

// applyAutoInboundFilters fills empty per-interface filters with an inbound-only
// expression derived from DiscoverInboundEndpoints. No-op when the user already
// set a BPF filter, or when discovery finds no usable listen ports.
func applyAutoInboundFilters(
	interfaces map[string]interfaceInfo,
	userFilters map[string]string,
	targetNetworkNamespaceOpt optionals.Optional[string],
	userBPFFilter string,
) (map[string]string, *InboundEndpoints) {
	if userBPFFilter != "" {
		return userFilters, nil
	}
	// Only auto-apply when every interface currently has an empty filter.
	for _, f := range userFilters {
		if f != "" {
			return userFilters, nil
		}
	}

	eps, err := DiscoverInboundEndpoints(targetNetworkNamespaceOpt)
	if err != nil {
		printer.Warningf("Auto inbound filter: endpoint discovery failed, capturing all traffic: %v\n", err)
		return userFilters, nil
	}
	if len(eps.ListenPorts) == 0 {
		printer.Infof("Auto inbound filter: no application listen ports found yet; capturing all traffic\n")
		return userFilters, &eps
	}

	expr := buildInboundBPFFilterForEndpoints(eps.LocalIPs, eps.ListenPorts)
	if expr == "" {
		printer.Warningf("Auto inbound filter: discovered ports %v but no local IPs; capturing all traffic\n", eps.ListenPorts)
		return userFilters, &eps
	}

	out := make(map[string]string, len(userFilters))
	for name := range interfaces {
		out[name] = expr
	}
	printer.Infof("Auto inbound-only capture enabled: ports=%v ips=%v\n", eps.ListenPorts, formatIPs(eps.LocalIPs))
	return out, &eps
}

func formatIPs(ips []net.IP) []string {
	s := make([]string, len(ips))
	for i, ip := range ips {
		s[i] = ip.String()
	}
	return s
}
