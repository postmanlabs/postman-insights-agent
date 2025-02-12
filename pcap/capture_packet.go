//go:build linux

package pcap

import (
	"time"

	"github.com/akitasoftware/go-utils/optionals"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

func (p *pcapImpl) capturePackets(done <-chan struct{}, interfaceName, bpfFilter string, _ optionals.Optional[string]) (<-chan gopacket.Packet, error) {
	handle, err := pcap.OpenLive(interfaceName, defaultSnapLen, true, pcap.BlockForever)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open pcap to %s", interfaceName)
	}
	if bpfFilter != "" {
		if err := handle.SetBPFFilter(bpfFilter); err != nil {
			handle.Close()
			return nil, errors.Wrap(err, "failed to set BPF filter")
		}
	}

	// Creating the packet source takes some time - do it here so the caller can
	// be confident that pakcets are being watched after this function returns.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	pktChan := packetSource.Packets()

	// TODO: tune the packet channel buffer
	wrappedChan := make(chan gopacket.Packet, 10)
	go func() {
		// Closing the handle can take a long time, so we close wrappedChan first to
		// allow the packet consumer to advance with its processing logic while we
		// wait for the handle to close in this goroutine.
		defer func() {
			close(wrappedChan)
			handle.Close()
		}()

		startTime := time.Now()
		count := 0
		for {
			select {
			case <-done:
				return
			case pkt, ok := <-pktChan:
				if ok {
					wrappedChan <- pkt

					if count == 0 {
						ttfp := time.Now().Sub(startTime)
						printer.Debugf("Time to first packet on %s: %s\n", interfaceName, ttfp)
					}
					count += 1
				} else {
					return
				}
			}
		}
	}()
	return wrappedChan, nil
}
