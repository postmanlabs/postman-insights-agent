package pcap

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/memview"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/google/uuid"
	"github.com/postmanlabs/postman-insights-agent/capturestats"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
)

// A buffer with a cursor that's advanced as data is consumed
// +-----------------------------------+
// | advanced  | remaining             |
// +-----------------------------------+
// |           ^ cursor
type parseBuffer struct {
	buf    memview.MemView
	cursor int64
}

func newParseBuffer(buf memview.MemView) parseBuffer {
	return parseBuffer{
		buf:    buf,
		cursor: 0,
	}
}

func (b *parseBuffer) buffer() memview.MemView {
	return b.buf.SubView(b.cursor, b.buf.Len())
}

func (b *parseBuffer) advance(count int64) {
	b.cursor += count
}

func (b *parseBuffer) pos() int64 {
	return b.cursor
}

func (b *parseBuffer) remaining() int64 {
	return b.buf.Len() - b.cursor
}

// tcpFlow represents a uni-directional flow of TCP segments along with a
// bidirectional ID that identifies the tcpFlow in the opposite direction.
// Writes come from TCP assembler via tcpStream, while reads come from users
// of this struct.
type tcpFlow struct {
	stream *tcpStream

	netFlow gopacket.Flow // constant
	tcpFlow gopacket.Flow // constant

	// Netns-wide locals for Direction (shared across both flows).
	directionHint *DirectionHint

	// Non-nil if there is an active parser for this flow.
	currentParser akinet.TCPParser

	// Time associated with the first packet of the message being parsed
	parseStart time.Time

	// Accept-time synthetic pair allocation for currentParser, if any. Rolled
	// back if the parse fails or is abandoned before a successful emit.
	currentPairSeq  reassembly.Sequence
	currentPairKind pairAllocKind

	// How much data that was left unused when determining parser, awaiting for more data.
	// This is a hack to flush data when the flow terminates before a parser has
	// been selected since reassembled does not get invoked on stream end even if
	// we use KeepFrom to keep data inside ScatterGather in a previous call to
	// reassembled.
	unparsedByteCnt int64
}

func newTCPFlow(stream *tcpStream, nf, tf gopacket.Flow, directionHint *DirectionHint) *tcpFlow {
	return &tcpFlow{
		stream:        stream,
		netFlow:       nf,
		tcpFlow:       tf,
		directionHint: directionHint,
	}
}

func (f *tcpFlow) handleUnparseable(t time.Time, size int64) {
	if size > 0 {
		f.stream.sink.Enqueue(f.toPNT(t, t, akinet.DroppedBytes(size)))
	}
}

// Handles reassmbled TCP flow data.
func (f *tcpFlow) reassembled(sg reassembly.ScatterGather) {
	_, _, isEnd, _ := sg.Info()

	available, _ := sg.Lengths()
	mv := memview.New(sg.Fetch(available))
	buf := newParseBuffer(mv)

	printer.V(6).Infof("reassembled with %d bytes, isEnd=%v\n", buf.remaining(), isEnd)

	// Close terminated stream. Finish parsing whatever was in flight.
	if isEnd && buf.remaining() == 0 && f.currentParser != nil {
		f.parseNext(&buf, isEnd, sg)
	}

	// One call can carry many messages, e.g. the backlog the assembler releases
	// all at once when it skips a gap left by a dropped packet. Parse every
	// complete message now: the next call only comes with this direction's next
	// packet, so parsing one per call would never catch up on the backlog.
	for buf.remaining() > 0 {
		if f.currentParser == nil {
			if !f.makeParser(sg, &buf, isEnd) {
				return
			}
		}

		f.parseNext(&buf, isEnd, sg)
	}
}

func (f *tcpFlow) makeParser(sg reassembly.ScatterGather, buf *parseBuffer, isEnd bool) bool {
	// Try to create a new parser.
	fact, decision, discardFront := f.stream.factorySelector.Select(buf.buffer(), isEnd)
	if discardFront > 0 {
		printer.V(6).Infof("discarding %d bytes discarded by all parsers\n", discardFront)
		f.handleUnparseable(sg.CaptureInfo(int(buf.pos())).Timestamp, discardFront)
		buf.advance(discardFront)
	}

	switch decision {
	case akinet.NeedMoreData:
		// Keep data for next reassembled call.
		printer.V(6).Infof("NeedMoreData to determine parser\n")
		sg.KeepFrom(int(buf.pos()))
		f.unparsedByteCnt = buf.remaining()
		return false
	case akinet.Reject:
		printer.V(6).Infof("Reject by all parsers\n")
		f.unparsedByteCnt = 0
		return false
	case akinet.Accept:
		printer.V(6).Infof("Accept by %s\n", fact.Name())
		f.unparsedByteCnt = 0

		acForFirstByte := sg.AssemblerContext(int(buf.pos()))
		ctx, ok := acForFirstByte.(*assemblerCtxWithSeq)
		if !ok {
			// Previously we errored in this case:
			printer.V(6).Infof("received AssemblerContext %v without TCP seq info, treating %s data as raw bytes\n", acForFirstByte, fact.Name())
			// but a user ran into quite a lot of them.  One theory is that this occurs when the HTTP response is in the
			// second (or later) page of a reassembly buffer.  A test validates that, but there might be other causes
			// that we don't yet understand.
			// So, track the error count but don't spam the log.
			if acForFirstByte == nil {
				f.stream.stats.IncrNilAssemblerContext()
			} else {
				f.stream.stats.IncrBadAssemblerContextType()
			}

			// Also record which half of the exchange we just threw away. The
			// counters above are shared by both directions, so on their own they
			// cannot tell us whether we are losing requests or responses --
			// which is the question, since a lost response leaves a witness with
			// no response half while a lost request leaves no witness at all.
			countDiscardedByParserKind(f.stream.stats, fact.Name())
			switch fact.Name() {
			case httpRequestParserFactoryName:
				f.reportTelemetryEvent("pcap_parser_discarded_request")
			case httpResponseParserFactoryName:
				f.reportTelemetryEvent("pcap_parser_discarded_response")
			}

			f.handleUnparseable(sg.CaptureInfo(int(buf.pos())).Timestamp, int64(buf.remaining()))
			return false
		}
		if f.stream.pairSeq != nil && isHTTPParserFactory(fact) {
			// Synthetic pairing: ignore real TCP seq/ack; use per-connection
			// FIFO ordinal (see pairing.go). Scoped to HTTP/1.x only.
			synthSeq, kind := f.stream.pairSeq.pairSeqForFactory(fact)
			f.currentParser = fact.CreateParser(f.stream.bidiID, synthSeq, synthSeq)
			f.currentPairSeq = synthSeq
			f.currentPairKind = kind
		} else {
			f.currentParser = fact.CreateParser(f.stream.bidiID, ctx.seq, ctx.ack)
			f.currentPairKind = pairAllocNone
		}
		f.parseStart = ctx.GetCaptureInfo().Timestamp
		return true
	default:
		printer.Errorf("unsupported decision type %s, treating data as raw bytes\n", decision)
		f.handleUnparseable(sg.CaptureInfo(int(buf.pos())).Timestamp, buf.remaining())
		return false
	}
}

// Parses buf (starting at its current position) to produce the next message.
// If parse is successful, it enqueues the message to the consumer.
func (f *tcpFlow) parseNext(buf *parseBuffer, isEnd bool, sg reassembly.ScatterGather) {
	pnc, unused, numBytesConsumed, err := f.currentParser.Parse(buf.buffer(), isEnd)
	buf.advance(buf.remaining() - unused.Len())

	if err != nil {
		// Parser failed, return all the bytes passed to the parser so at least we
		// can still perform leak detection on the raw bytes.
		f.handleUnparseable(f.parseStart, numBytesConsumed)

		f.rollbackCurrentPairSeq()
		f.currentParser = nil
		f.parseStart = time.Time{}

		telemetry.RateLimitError("parser", err)
	} else if pnc != nil {
		// Parsing complete.
		ac := sg.AssemblerContext(int(buf.pos() - 1))
		var parseEnd time.Time
		if ac != nil {
			parseEnd = ac.GetCaptureInfo().Timestamp
		} else {
			// We could use time.Now() but because this case seems to
			// appear when we have called FlushCloseOlderThan, it would
			// probably be misleading.
			// TODO: what else can we log here to help identify what's going on?
			printer.V(6).Infof("AssemblerContext is nil for packet started at %v\n", f.parseStart)
			f.stream.stats.IncrNilAssemblerContextAfterParse()
			parseEnd = f.parseStart
		}
		f.stream.sink.Enqueue(f.toPNT(f.parseStart, parseEnd, pnc))

		f.currentPairKind = pairAllocNone
		f.currentParser = nil
		f.parseStart = time.Time{}
	}
}

// Names passed here must already carry the pcap_ source prefix, the same as
// this package's interval counters (pcap_packets_received): the caller hands us
// an unprefixed reporter precisely because we name our own metrics.
func (f *tcpFlow) reportTelemetryEvent(event string) {
	if f.stream.telemetryCountReporter != nil {
		f.stream.telemetryCountReporter(event, 1)
	}
}

func (f *tcpFlow) rollbackCurrentPairSeq() {
	if f.stream.pairSeq != nil && f.currentPairKind != pairAllocNone {
		f.stream.pairSeq.rollbackPairSeq(f.currentPairSeq, f.currentPairKind)
	}
	f.currentPairKind = pairAllocNone
}

// Marks this flow as finished.
func (f *tcpFlow) reassemblyComplete() {
	if f.currentParser != nil {
		// We were in the middle of parsing something, give up.
		pnc, unused, numBytesConsumed, err := f.currentParser.Parse(memview.New(nil), true)
		if err != nil {
			f.handleUnparseable(f.parseStart, numBytesConsumed)
			f.rollbackCurrentPairSeq()
		} else if pnc != nil {
			printer.V(6).Infof("ReassemblyComplete parsed additional network traffic with ts: %v", f.parseStart)
			f.stream.sink.Enqueue(f.toPNT(f.parseStart, f.parseStart, pnc))
			f.currentPairKind = pairAllocNone
			f.handleUnparseable(f.parseStart, unused.Len())
		} else {
			// Forced end with no complete message — undo Accept-time allocation.
			f.rollbackCurrentPairSeq()
		}
		f.currentParser = nil
		f.parseStart = time.Time{}
	} else if f.unparsedByteCnt > 0 {
		// The flow terminated before a parser has been selected, flush any bytes
		// that were buffered waiting for more data to determine parse.
		// We estimate the time with current time instead of tracking a separate
		// context since unusedAcceptBuf is unlikely to be used and is almost
		// certainly very small in size.
		f.stream.sink.Enqueue(f.toPNT(f.stream.clock.Now(), f.stream.clock.Now(), akinet.DroppedBytes(f.unparsedByteCnt)))
	}
}

func (f *tcpFlow) toPNT(firstPacketTime time.Time, lastPacketTime time.Time,
	c akinet.ParsedNetworkContent,
) akinet.ParsedNetworkTraffic {
	var pncType string
	var transportSecurity akinet.TransportSecurity

	switch c.(type) {
	case akinet.HTTPRequest:
		pncType = "request"
		transportSecurity = akinet.TransportSecurityPlaintext
	case akinet.HTTPResponse:
		pncType = "response"
		transportSecurity = akinet.TransportSecurityPlaintext
	case akinet.DroppedBytes:
		pncType = "dropped_bytes"
	default:
		pncType = "unknown"
	}

	if firstPacketTime.IsZero() || lastPacketTime.IsZero() {
		now := f.stream.clock.Now()
		printer.V(6).Infof("ParsedNetworkTraffic with zero value packet timestamps. type: %v first: %v last: %v now: %v", pncType, firstPacketTime, lastPacketTime, now)
		f.stream.stats.IncrZeroValuePacketTimestamp()

		if firstPacketTime.IsZero() {
			firstPacketTime = now
		}
		if lastPacketTime.IsZero() {
			lastPacketTime = now
		}
	}
	if lastPacketTime.Before(firstPacketTime) {
		printer.V(6).Infof("ParsedNetworkTraffic with last packet before first packet. type: %v first: %v last: %v", pncType, firstPacketTime, lastPacketTime)
		f.stream.stats.IncrLastPacketBeforeFirstPacket()

		lastPacketTime = firstPacketTime
	}

	// Endpoint interpretation logic from
	// https://github.com/google/gopacket/blob/0ad7f2610e344e58c1c95e2adda5c3258da8e97b/layers/endpoints.go#L30
	srcE, dstE := f.netFlow.Endpoints()
	srcP, dstP := f.tcpFlow.Endpoints()

	srcIP := net.IP(srcE.Raw())
	dstIP := net.IP(dstE.Raw())
	srcPort := int(binary.BigEndian.Uint16(srcP.Raw()))
	dstPort := int(binary.BigEndian.Uint16(dstP.Raw()))

	return akinet.ParsedNetworkTraffic{
		SrcIP:             srcIP,
		SrcPort:           srcPort,
		DstIP:             dstIP,
		DstPort:           dstPort,
		Content:           c,
		ObservationTime:   firstPacketTime,
		FinalPacketTime:   lastPacketTime,
		Direction:         classifyHTTPDirection(c, srcIP, dstIP, srcPort, dstPort, f.directionHint),
		Interface:         f.stream.interfaceName,
		TransportSecurity: transportSecurity,
	}
}

// tcpStream represents a pair of uni-directional tcpFlows. It implements
// reassembly.Stream interface to receive reassembled packets for BOTH flows,
// which it then directs to the correct tcpFlow.
type tcpStream struct {
	clock  clockWrapper     // constant
	bidiID akinet.TCPBidiID // constant

	// Network layer flow.
	netFlow gopacket.Flow

	// flows is populated upon seeing the first packet.
	flows map[reassembly.TCPFlowDirection]*tcpFlow

	factorySelector        akinet.TCPParserFactorySelector
	sink                   ParsedNetworkTrafficSink
	stats                  *capturestats.Stats
	telemetryCountReporter func(string, uint64)

	// Shared by both flows of this connection when synthetic TCP pairing is
	// enabled; nil otherwise. See pairing.go.
	pairSeq *pairSequencer

	directionHint *DirectionHint

	interfaceName string
}

func newTCPStream(clock clockWrapper, netFlow gopacket.Flow, sink ParsedNetworkTrafficSink, fs akinet.TCPParserFactorySelector, stats *capturestats.Stats, useSyntheticPairing bool, directionHint *DirectionHint, telemetryCountReporter func(string, uint64), iface string) *tcpStream {
	var pairSeq *pairSequencer
	if useSyntheticPairing {
		pairSeq = newPairSequencer()
	}
	return &tcpStream{
		clock:                  clock,
		bidiID:                 akinet.TCPBidiID(uuid.New()),
		netFlow:                netFlow,
		factorySelector:        fs,
		sink:                   sink,
		stats:                  stats,
		pairSeq:                pairSeq,
		directionHint:          directionHint,
		telemetryCountReporter: telemetryCountReporter,
		interfaceName:          iface,
	}
}

func (c *tcpStream) Accept(tcp *layers.TCP, _ gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, _ reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// We always force the TCP stream to start because we cannot guarantee that we
	// will ever observe the SYN packet. For example, we could be looking at an
	// existing connection that is actively reused by HTTP traffic. Without the
	// forced start, the stream will be held up by the assembler forever and we'll
	// never get a change to analyze its data.
	*start = true

	if c.flows == nil {
		// We are accepting the first packet for this connection.
		// Create the 2 flows now that we know the directionality.
		// We speculatively create a tcpFlow for the opposite direction. Reads
		// from from the speculative flow will block until it receives reassembled
		// data from this tcpStream or it is garbage collected by the assembler
		// after streamTimeout.
		tf, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(tcp.SrcPort), layers.NewTCPPortEndpoint(tcp.DstPort))
		s1 := newTCPFlow(c, c.netFlow, tf, c.directionHint)
		s2 := newTCPFlow(c, c.netFlow.Reverse(), tf.Reverse(), c.directionHint)
		c.flows = map[reassembly.TCPFlowDirection]*tcpFlow{
			dir:           s1,
			dir.Reverse(): s2,
		}
	}

	// Output some metadata for the current packet.
	{
		srcE, dstE := c.netFlow.Endpoints()
		c.sink.Enqueue(akinet.ParsedNetworkTraffic{
			SrcIP:   net.IP(srcE.Raw()),
			SrcPort: int(tcp.SrcPort),
			DstIP:   net.IP(dstE.Raw()),
			DstPort: int(tcp.DstPort),
			Content: akinet.TCPPacketMetadata{
				ConnectionID:        akid.NewConnectionID(uuid.UUID(c.bidiID)),
				SYN:                 tcp.SYN,
				ACK:                 tcp.ACK,
				FIN:                 tcp.FIN,
				RST:                 tcp.RST,
				PayloadLength_bytes: len(tcp.LayerPayload()),
			},
			ObservationTime: ac.GetCaptureInfo().Timestamp,
			Interface:       c.interfaceName,
		})
	}

	// Accept everything, even if the packet might violate the TCP state machine
	// and get rejected by the client or server's TCP stack. We do this because we
	// are interested in detecting all dataflows, not just ones from valid TCP
	// connections.
	// We reassembly library does guarantee to deliver data in stream order, so we
	// don't need to worry about getting out-of-order or duplicate data.
	return true
}

// Handles reassmbled TCP stream data.
func (c *tcpStream) ReassembledSG(sg reassembly.ScatterGather, _ reassembly.AssemblerContext) {
	if c.flows == nil {
		printer.Errorf("received reassembled TCP stream data before accept, dropping packets\n")
		return
	}
	dir, _, _, _ := sg.Info()
	c.flows[dir].reassembled(sg)
}

func (c *tcpStream) ReassemblyComplete(_ reassembly.AssemblerContext) bool {
	for _, s := range c.flows {
		s.reassemblyComplete()
	}

	// Remove connection from the pool
	return true
}
