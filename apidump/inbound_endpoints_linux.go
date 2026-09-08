//go:build linux

package apidump

import (
	"net"

	"github.com/akitasoftware/go-utils/optionals"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"
)

// DiscoverInboundEndpoints finds UP interface IPs and TCP LISTEN ports in the
// target network namespace (or the current process ns when none is set).
// Mesh/admin listen ports (Istio 15000–15090, ssh) are omitted.
func DiscoverInboundEndpoints(targetNetworkNamespaceOpt optionals.Optional[string]) (InboundEndpoints, error) {
	eps, _, err := discoverInboundEndpointsDetailed(targetNetworkNamespaceOpt)
	return eps, err
}

func discoverInboundEndpointsDetailed(targetNetworkNamespaceOpt optionals.Optional[string]) (InboundEndpoints, []uint16, error) {
	nsPath, hasNS := targetNetworkNamespaceOpt.Get()
	if !hasNS || nsPath == "" {
		return discoverInboundEndpointsDetailedCurrentNS()
	}

	targetNs, err := ns.GetNS(nsPath)
	if err != nil {
		return InboundEndpoints{}, nil, errors.Wrapf(err, "can't get network namespace %s", nsPath)
	}
	defer targetNs.Close()

	var (
		ips                []net.IP
		appPorts, rawPorts []uint16
	)

	// Ports: prefer /proc/<pid>/net/tcp{,6} from the DaemonSet ns path (no
	// setns). Fall back to /proc/net inside setns only when the path is not
	// pid-scoped (e.g. a named netns file).
	if _, _, ok := procRootAndPIDFromNSPath(nsPath); ok {
		appPorts, rawPorts, err = discoverListenPortsForNetNS(nsPath)
		if err != nil {
			return InboundEndpoints{}, nil, err
		}
		if err := targetNs.Do(func(_ ns.NetNS) error {
			var e error
			ips, e = listLocalIPs()
			return e
		}); err != nil {
			return InboundEndpoints{}, nil, err
		}
	} else {
		if err := targetNs.Do(func(_ ns.NetNS) error {
			var e error
			ips, e = listLocalIPs()
			if e != nil {
				return e
			}
			appPorts, rawPorts, e = discoverListenPortsForNetNS("")
			return e
		}); err != nil {
			return InboundEndpoints{}, nil, err
		}
	}

	return InboundEndpoints{LocalIPs: ips, ListenPorts: appPorts}, rawPorts, nil
}

func discoverInboundEndpointsDetailedCurrentNS() (InboundEndpoints, []uint16, error) {
	ips, err := listLocalIPs()
	if err != nil {
		return InboundEndpoints{}, nil, err
	}
	appPorts, rawPorts, err := listListenPortsFromProcFiles(
		[]string{"/proc/net/tcp", "/proc/net/tcp6"},
		defaultExcludedListenPorts,
	)
	if err != nil {
		return InboundEndpoints{}, nil, err
	}
	return InboundEndpoints{LocalIPs: ips, ListenPorts: appPorts}, rawPorts, nil
}
