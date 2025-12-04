package pcap

import (
	"net"
	"os"
	"time"

	"github.com/akitasoftware/go-utils/optionals"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// fileCaptureReader implements pcapWrapper for reading packets from a pcapng file.
// This is used to read HTTPS traffic captured by eCapture into pcapng format.
//
// Unlike live interface capture, file capture reads from a continuously-growing file
// (similar to `tail -f`). When EOF is reached, the reader polls the file for new packets.
type fileCaptureReader struct {
	filePath string
}

// NewFileCaptureReader creates a new file-based packet reader for the given pcapng file.
func NewFileCaptureReader(filePath string) *fileCaptureReader {
	return &fileCaptureReader{
		filePath: filePath,
	}
}

// capturePackets reads packets from a pcapng file and returns them via a channel.
// The function continuously polls the file for new packets (tail -f behavior).
//
// Parameters:
//   - done: Channel to signal when to stop reading
//   - interfaceName: Ignored for file capture (used for logging only)
//   - bpfFilter: Ignored for file capture (eCapture already filters traffic)
//   - targetNetworkNamespaceOpt: Ignored for file capture
//
// Returns:
//   - Channel of packets read from the file
//   - Error if file cannot be opened or reading fails
func (f *fileCaptureReader) capturePackets(
	done <-chan struct{},
	_, _ string,
	_ optionals.Optional[string],
) (<-chan gopacket.Packet, error) {
	// Wait for file to exist (eCapture might not have created it yet)
	if err := f.waitForFile(done, 30*time.Second); err != nil {
		return nil, err
	}

	// Open the pcapng file
	handle, err := pcap.OpenOffline(f.filePath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open HTTPS capture file %s", f.filePath)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	pktChan := packetSource.Packets()

	wrappedChan := make(chan gopacket.Packet, 10)

	go func() {
		defer func() {
			close(wrappedChan)
			handle.Close()
			printer.Debugf("File capture reader closed for %s\n", f.filePath)
		}()

		packetsRead := 0
		eofCount := 0

		for {
			select {
			case <-done:
				printer.Debugf("File capture stopped, read %d packets from %s\n", packetsRead, f.filePath)
				return

			case pkt, ok := <-pktChan:
				if !ok {
					// EOF reached - file might still be growing
					eofCount++

					if eofCount%10 == 0 {
						printer.Debugf("File capture EOF count: %d for %s (packets read: %d)\n",
							eofCount, f.filePath, packetsRead)
					}

					// Wait before polling again (eCapture writes in batches)
					select {
					case <-done:
						return
					case <-time.After(500 * time.Millisecond):
						// Try reopening file to read new packets
						handle.Close()
						handle, err = pcap.OpenOffline(f.filePath)
						if err != nil {
							printer.Errorf("Failed to reopen HTTPS capture file %s: %v\n", f.filePath, err)
							return
						}
						packetSource = gopacket.NewPacketSource(handle, handle.LinkType())
						pktChan = packetSource.Packets()
					}
					continue
				}

				packetsRead++
				eofCount = 0 // Reset EOF counter when packets are read

				if packetsRead%100 == 0 {
					printer.Debugf("File capture read %d packets from %s\n", packetsRead, f.filePath)
				}

				wrappedChan <- pkt
			}
		}
	}()

	return wrappedChan, nil
}

// waitForFile polls for the file to exist with a timeout.
// This handles the case where eCapture hasn't created the file yet when apidump starts.
func (f *fileCaptureReader) waitForFile(done <-chan struct{}, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for {
		if _, err := os.Stat(f.filePath); err == nil {
			printer.Debugf("HTTPS capture file found: %s\n", f.filePath)
			return nil
		}

		if time.Now().After(deadline) {
			return errors.Errorf("HTTPS capture file %s not found after %v", f.filePath, timeout)
		}

		select {
		case <-done:
			return errors.New("stopped waiting for HTTPS capture file")
		case <-time.After(1 * time.Second):
			// Continue waiting
			printer.Debugf("Waiting for HTTPS capture file: %s\n", f.filePath)
		}
	}
}

// getInterfaceAddrs is not applicable for file capture.
// Returns nil since we're not capturing from a network interface.
func (f *fileCaptureReader) getInterfaceAddrs(_ string) ([]net.IP, error) {
	return nil, nil
}
