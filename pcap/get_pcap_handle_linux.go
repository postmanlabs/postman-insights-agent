//go:build linux

package pcap

import (
	"time"

	"github.com/akitasoftware/go-utils/optionals"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
)

func GetPcapHandle(
	interfaceName string,
	snaplen int32,
	promisc bool,
	timeout time.Duration,
	targetNetworkNamespaceOpt optionals.Optional[string],
) (*pcap.Handle, error) {
	var (
		handle *pcap.Handle
		err    error
	)

	if targetNetworkNamespace, exists := targetNetworkNamespaceOpt.Get(); exists {
		// Switch to the target network namespace.
		targetNs, err := ns.GetNS(targetNetworkNamespace)
		if err != nil {
			return nil, errors.Wrapf(err, "can't get network namespace %s", targetNetworkNamespace)
		}
		//TODO(K8s-MNS) Is this right place to close? Same in net.go
		defer targetNs.Close()

		// Open the pcap handle in the target network namespace.
		err = targetNs.Do(func(host ns.NetNS) error {
			var err error
			handle, err = pcap.OpenLive(interfaceName, snaplen, promisc, timeout)
			if err != nil {
				return errors.Wrapf(err, "failed to open pcap to %s/%s", targetNetworkNamespace, interfaceName)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		// Open the pcap handle in the agent's network namespace.
		handle, err = pcap.OpenLive(interfaceName, snaplen, promisc, timeout)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to open pcap to %s", interfaceName)
		}
	}

	return handle, nil
}
