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
	bufferSize optionals.Optional[int32],
	targetNetworkNamespaceOpt optionals.Optional[string],
) (*pcap.Handle, error) {
	var (
		handle *pcap.Handle
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
			handle, err = getPcapHandle(interfaceName, snaplen, promisc, timeout, bufferSize)
			if err != nil {
				return errors.Wrapf(err, "failed to open pcap to %s/%s", targetNetworkNamespace, interfaceName)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		return getPcapHandle(interfaceName, snaplen, promisc, timeout, bufferSize)
	}

	return handle, nil
}

func getPcapHandle(
	interfaceName string,
	snaplen int32,
	promisc bool,
	timeout time.Duration,
	bufferSize optionals.Optional[int32],
) (*pcap.Handle, error) {
	inactive, err := pcap.NewInactiveHandle(interfaceName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open inactive pcap to %s", interfaceName)
	}

	cleanup := true
	defer func() {
		if cleanup {
			inactive.CleanUp()
		}
	}()

	err = inactive.SetSnapLen(int(snaplen))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to set snaplen to %d", snaplen)
	}

	err = inactive.SetPromisc(promisc)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to set promisc to %v", promisc)
	}

	err = inactive.SetTimeout(timeout)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to set timeout to %v", timeout)
	}

	if size, ok := bufferSize.Get(); ok {
		err = inactive.SetBufferSize(int(size))
		if err != nil {
			return nil, errors.Wrapf(err, "failed to set buffer size to %d", size)
		}
	}

	handle, err := inactive.Activate()
	if err != nil {
		return nil, errors.Wrap(err, "failed to activate pcap handle")
	}

	cleanup = false

	return handle, nil
}
