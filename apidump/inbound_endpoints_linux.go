//go:build linux

package apidump

import (
	"github.com/akitasoftware/go-utils/optionals"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"
)

// DiscoverInboundEndpoints finds UP interface IPs and TCP LISTEN ports in the
// target network namespace (or the current process ns when none is set).
// Mesh/admin listen ports (Istio 15000–15090, ssh) are omitted.
func DiscoverInboundEndpoints(targetNetworkNamespaceOpt optionals.Optional[string]) (InboundEndpoints, error) {
	if nsPath, ok := targetNetworkNamespaceOpt.Get(); ok && nsPath != "" {
		targetNs, err := ns.GetNS(nsPath)
		if err != nil {
			return InboundEndpoints{}, errors.Wrapf(err, "can't get network namespace %s", nsPath)
		}
		defer targetNs.Close()
		var out InboundEndpoints
		if err := targetNs.Do(func(_ ns.NetNS) error {
			var e error
			out, e = discoverInboundEndpointsInCurrentNS()
			return e
		}); err != nil {
			return InboundEndpoints{}, err
		}
		return out, nil
	}
	return discoverInboundEndpointsInCurrentNS()
}
