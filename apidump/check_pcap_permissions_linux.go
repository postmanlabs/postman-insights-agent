//go:build linux

package apidump

import (
	"sync"
	"time"

	"github.com/akitasoftware/go-utils/optionals"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/google/gopacket/pcap"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
)

// Check if we have permission to capture packets on the given set of
// interfaces.
func checkPcapPermissions(interfaces map[string]interfaceInfo, targetNetworkNamespaceOpt optionals.Optional[string]) map[string]error {
	printer.Debugf("Checking pcap permissions...\n")
	start := time.Now()

	var wg sync.WaitGroup
	wg.Add(len(interfaces))
	errChan := make(chan *pcapPermErr, len(interfaces)) // buffered enough to never block
	for iface := range interfaces {
		go func(iface string) {
			defer wg.Done()
			if targetNetworkNamespace, exists := targetNetworkNamespaceOpt.Get(); exists {
				// Switch to the target network namespace.
				targetNs, err := ns.GetNS(targetNetworkNamespace)
				if err != nil {
					telemetry.Error("pcap permissions", err)
					errChan <- &pcapPermErr{iface: iface, err: err}
					return
				}
				defer targetNs.Close()

				err = targetNs.Do(func(host ns.NetNS) error {
					var err error
					h, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
					if err != nil {
						return err
					}
					h.Close()
					return nil
				})

				if err != nil {
					telemetry.Error("pcap permissions", err)
					errChan <- &pcapPermErr{iface: iface, err: err}
					return
				}
			} else {
				h, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
				if err != nil {
					telemetry.Error("pcap permissions", err)
					errChan <- &pcapPermErr{iface: iface, err: err}
					return
				}
				h.Close()
			}
		}(iface)
	}

	wg.Wait()
	printer.Debugf("Check pcap permission done after %s\n", time.Since(start))
	close(errChan)
	errs := map[string]error{}
	for pe := range errChan {
		if pe != nil {
			errs[pe.iface] = pe
		}
	}
	return errs
}
