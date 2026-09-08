//go:build !linux

package apidump

import (
	"github.com/akitasoftware/go-utils/optionals"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// DiscoverInboundEndpoints finds UP interface IPs and TCP LISTEN ports in the
// current process network namespace. On non-Linux platforms, targetNetworkNamespace
// is ignored (setns is unavailable).
func DiscoverInboundEndpoints(targetNetworkNamespaceOpt optionals.Optional[string]) (InboundEndpoints, error) {
	eps, _, err := discoverInboundEndpointsDetailed(targetNetworkNamespaceOpt)
	return eps, err
}

func discoverInboundEndpointsDetailed(targetNetworkNamespaceOpt optionals.Optional[string]) (InboundEndpoints, []uint16, error) {
	if nsPath, ok := targetNetworkNamespaceOpt.Get(); ok && nsPath != "" {
		printer.Warningf("Auto inbound filter: network namespace switching is unsupported on this OS; discovering endpoints in the agent namespace (requested %s)\n", nsPath)
	}
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
