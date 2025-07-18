package pcap

import (
	"time"

	"github.com/akitasoftware/akita-libs/akinet"
	akihttp "github.com/akitasoftware/akita-libs/akinet/http"
	akihttp2 "github.com/akitasoftware/akita-libs/akinet/http2"
	"github.com/akitasoftware/akita-libs/akinet/tls"
	"github.com/akitasoftware/akita-libs/buffer_pool"
	. "github.com/akitasoftware/akita-libs/client_telemetry"
	"github.com/akitasoftware/go-utils/optionals"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/trace"
)

func Collect(
	stop <-chan struct{},
	intf string,
	bpfFilter string,
	targetNetworkNamespaceOpt optionals.Optional[string],
	bufferShare float32,
	parseTCPAndTLS bool,
	proc trace.Collector,
	packetCount trace.PacketCountConsumer,
	pool buffer_pool.BufferPool,
) error {
	defer proc.Close()

	facts := []akinet.TCPParserFactory{
		akihttp.NewHTTPRequestParserFactory(pool),
		akihttp.NewHTTPResponseParserFactory(pool),
		akihttp2.NewHTTP2PrefaceParserFactory(),
	}
	if parseTCPAndTLS {
		facts = append(facts,
			tls.NewTLSClientParserFactory(),
			tls.NewTLSServerParserFactory(),
		)
	}

	parser := NewNetworkTrafficParser(bufferShare)

	if packetCount != nil {
		parser.InstallObserver(CountTcpPackets(intf, packetCount))
	}

	parsedChan, err := parser.ParseFromInterface(intf, bpfFilter, targetNetworkNamespaceOpt, stop, facts...)
	if err != nil {
		return errors.Wrap(err, "couldn't start parsing from interface")
	}

	startTime := time.Now()
	bufferTimeSum := 0 * time.Second
	intervalLength := 1 * time.Minute
	for t := range parsedChan {
		now := time.Now()
		if now.Sub(startTime) >= intervalLength {
			bufferLength := float64(bufferTimeSum.Nanoseconds()) / float64(intervalLength.Nanoseconds())
			printer.Debugf("Aproximate parsed-network-traffic buffer length: %v", bufferLength)
			bufferTimeSum = 0 * time.Second
			startTime = now
		}

		bufferTimeSum += now.Sub(t.ObservationTime)
		t.Interface = intf
		err := proc.Process(t)
		t.Content.ReleaseBuffers()
		if err != nil {
			return err
		}
	}

	return nil
}

// Observe every captured TCP segment here
func CountTcpPackets(ifc string, packetCount trace.PacketCountConsumer) NetworkTrafficObserver {
	observer := func(p gopacket.Packet) {
		if tcpLayer := p.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			packetCount.Update(PacketCounts{
				Interface:  ifc,
				SrcPort:    int(tcp.SrcPort),
				DstPort:    int(tcp.DstPort),
				TCPPackets: 1,
			})
		}
	}
	return NetworkTrafficObserver(observer)
}
