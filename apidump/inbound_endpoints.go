package apidump

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/akitasoftware/go-utils/optionals"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/pcap"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// TCP state LISTEN in /proc/net/tcp{,6}.
const tcpListenState = "0A"

// How long / how often to wait for application listen ports when discovery
// initially finds none (app may bind after the container is Running).
// Overridable in tests.
var (
	inboundDiscoveryRetryTotal    = 15 * time.Second
	inboundDiscoveryRetryInterval = 500 * time.Millisecond
)

// Default ports excluded from auto inbound capture (admin / non-app).
// Mesh proxy ports are excluded via pcap.IsMeshProxyPort (shared with Direction).
// Apps that listen only on excluded ports will not get an auto filter applied
// for those ports; other listen ports in the same netns still apply.
var defaultExcludedListenPorts = map[uint16]struct{}{
	22: {}, // ssh
}

// Matches .../proc/<pid>/ns/net (DaemonSet uses /host/proc/<pid>/ns/net).
var procNSPathRE = regexp.MustCompile(`^(.*)/proc/(\d+)/ns/net$`)

// InboundEndpoints are local addresses and listen ports discovered in a
// capture network namespace for building an inbound-only BPF filter.
type InboundEndpoints struct {
	LocalIPs    []net.IP
	ListenPorts []uint16
}

// discoverListenPortsForNetNS lists LISTEN ports for the capture netns.
// Prefer /proc/<pid>/net/tcp{,6} derived from a DaemonSet ns path so we do not
// depend on /proc/net after setns (kernels have had stale /proc/net dcache
// bugs after CLONE_NEWNET). When the ns path is not pid-scoped, the caller
// must already be in the target netns and should pass nsPath="" to read
// /proc/net/tcp{,6}.
func discoverListenPortsForNetNS(nsPath string) (appPorts, rawPorts []uint16, err error) {
	if procRoot, pid, ok := procRootAndPIDFromNSPath(nsPath); ok {
		paths := []string{
			filepath.Join(procRoot, strconv.Itoa(pid), "net", "tcp"),
			filepath.Join(procRoot, strconv.Itoa(pid), "net", "tcp6"),
		}
		return listListenPortsFromProcFiles(paths, defaultExcludedListenPorts)
	}
	return listListenPortsFromProcFiles(
		[]string{"/proc/net/tcp", "/proc/net/tcp6"},
		defaultExcludedListenPorts,
	)
}

func procRootAndPIDFromNSPath(nsPath string) (procRoot string, pid int, ok bool) {
	m := procNSPathRE.FindStringSubmatch(nsPath)
	if m == nil {
		return "", 0, false
	}
	pid64, err := strconv.ParseInt(m[2], 10, 32)
	if err != nil || pid64 <= 0 {
		return "", 0, false
	}
	procRoot = m[1] + "/proc"
	return procRoot, int(pid64), true
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

func listListenPortsFromProcFiles(paths []string, exclude map[uint16]struct{}) (appPorts, rawPorts []uint16, err error) {
	seenRaw := map[uint16]struct{}{}
	seenApp := map[uint16]struct{}{}
	for _, name := range paths {
		f, openErr := os.Open(name)
		if openErr != nil {
			if os.IsNotExist(openErr) {
				continue
			}
			return nil, nil, errors.Wrapf(openErr, "open %s", name)
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
			if _, ok := seenRaw[port]; !ok {
				seenRaw[port] = struct{}{}
				rawPorts = append(rawPorts, port)
			}
			if shouldExcludeListenPort(port, exclude) {
				continue
			}
			if _, ok := seenApp[port]; ok {
				continue
			}
			seenApp[port] = struct{}{}
			appPorts = append(appPorts, port)
		}
		scanErr := sc.Err()
		_ = f.Close()
		if scanErr != nil {
			return nil, nil, errors.Wrapf(scanErr, "scan %s", name)
		}
	}
	return appPorts, rawPorts, nil
}

func shouldExcludeListenPort(port uint16, exclude map[uint16]struct{}) bool {
	if _, ok := exclude[port]; ok {
		return true
	}
	// Shared with pcap Direction tie-break (see pcap.IsMeshProxyPort).
	return pcap.IsMeshProxyPort(port)
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

	eps, rawPorts, err := discoverInboundEndpointsWithRetry(targetNetworkNamespaceOpt)
	if err != nil {
		printer.Warningf("Auto inbound filter: endpoint discovery failed, capturing all traffic: %v\n", err)
		return userFilters, nil
	}
	if len(eps.ListenPorts) == 0 {
		nsDesc := "current"
		if nsPath, ok := targetNetworkNamespaceOpt.Get(); ok && nsPath != "" {
			nsDesc = nsPath
		}
		if len(rawPorts) == 0 {
			printer.Infof("Auto inbound filter: no TCP LISTEN sockets in netns %s; capturing all traffic\n", nsDesc)
		} else {
			printer.Infof("Auto inbound filter: only mesh/admin listen ports %v in netns %s (no application ports); capturing all traffic\n", rawPorts, nsDesc)
		}
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

func discoverInboundEndpointsWithRetry(
	targetNetworkNamespaceOpt optionals.Optional[string],
) (eps InboundEndpoints, rawPorts []uint16, err error) {
	deadline := time.Now().Add(inboundDiscoveryRetryTotal)
	attempt := 0
	for {
		attempt++
		eps, rawPorts, err = discoverInboundEndpointsDetailed(targetNetworkNamespaceOpt)
		if err != nil {
			return InboundEndpoints{}, nil, err
		}
		if len(eps.ListenPorts) > 0 {
			if attempt > 1 {
				printer.Infof("Auto inbound filter: found application listen ports %v after %d attempt(s)\n", eps.ListenPorts, attempt)
			}
			return eps, rawPorts, nil
		}
		if time.Now().After(deadline) {
			return eps, rawPorts, nil
		}
		printer.Debugf("Auto inbound filter: no application listen ports yet (raw=%v), retrying...\n", rawPorts)
		time.Sleep(inboundDiscoveryRetryInterval)
	}
}

func formatIPs(ips []net.IP) []string {
	s := make([]string, len(ips))
	for i, ip := range ips {
		s[i] = ip.String()
	}
	return s
}
