package pcap

import (
	"time"

	"github.com/akitasoftware/go-utils/optionals"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
)

func GetPcapHandle(
	interfaceName string,
	snaplen int32,
	promisc bool,
	timeout time.Duration,
	_ optionals.Optional[string],
) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(interfaceName, snaplen, promisc, timeout)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open pcap to %s", interfaceName)
	}

	return handle, nil
}
