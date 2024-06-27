package apidump

import (
	"fmt"
	"sort"

	"github.com/akitasoftware/akita-libs/client_telemetry"
	"github.com/akitasoftware/go-utils/math"
	"github.com/postmanlabs/postman-insights-agent/env"
	"github.com/postmanlabs/postman-insights-agent/pcap"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/trace"
	"github.com/spf13/viper"
)

// Captures apidump progress.
type Summary struct {
	// Indicates whether this summary includes information about packets that did
	// not meet the BPF filters specified by the user.
	CapturingNegation bool

	Interfaces      map[string]interfaceInfo
	NegationFilters map[string]string
	NumUserFilters  int

	// Values that change over the course of apidump are pointers.
	FilterSummary    *trace.PacketCounter
	PrefilterSummary *trace.PacketCounter
	NegationSummary  *trace.PacketCounter
}

func NewSummary(
	capturingNegation bool,
	interfaces map[string]interfaceInfo,
	negationFilters map[string]string,
	numUserFilters int,
	filterSummary *trace.PacketCounter,
	prefilterSummary *trace.PacketCounter,
	negationSummary *trace.PacketCounter,
) *Summary {
	return &Summary{
		CapturingNegation: capturingNegation,
		Interfaces:        interfaces,
		NegationFilters:   negationFilters,
		NumUserFilters:    numUserFilters,
		FilterSummary:     filterSummary,
		PrefilterSummary:  prefilterSummary,
		NegationSummary:   negationSummary,
	}
}

// Dumps packet counters for packets captured and sent to the Akita backend.
// If the debug flag is set, also prints packets taht were captured but not
// sent to the backend.
func (s *Summary) PrintPacketCounts() {
	s.PrintPacketCountHighlights()

	if viper.GetBool("debug") {
		if len(s.NegationFilters) == 0 {
			DumpPacketCounters(printer.Stderr.Infof, s.Interfaces, s.FilterSummary, nil, true)
		} else {
			DumpPacketCounters(printer.Stderr.Infof, s.Interfaces, s.FilterSummary, s.NegationSummary, true)
		}
		if s.NumUserFilters > 0 {
			printer.Stderr.Debugf("+++ Counts before allow and exclude filters and sampling +++\n")
			DumpPacketCounters(printer.Stderr.Debugf, s.Interfaces, s.PrefilterSummary, nil, false)
		}
	}
}

// Summarize the top sources of traffic seen in a log-friendly format.
// This appears before PrintWarnings, and should highlight the raw data.
func (s *Summary) PrintPacketCountHighlights() {
	summaryLimit := 20
	top := s.FilterSummary.Summary(summaryLimit)

	totalTraffic := top.Total.TCPPackets
	if totalTraffic == 0 {
		// PrintWarnings already covers this case
		return
	}

	// If we hit the limit of the number of ports we tracked, mention so.
	// This should (hopefully) be unlikely.
	if top.ByPortOverflow != nil {
		printer.Stderr.Infof(
			"More than %d ports with traffic.  Showing the top %d of the first %d.\n",
			top.ByPortOverflowLimit, math.Min(summaryLimit, top.ByPortOverflowLimit), top.ByPortOverflowLimit,
		)
	}

	printer.Stderr.Infof("Top ports by traffic volume:\n")
	s.printPortHighlights(top)

	printer.Stderr.Infof("Top hosts by traffic volume:\n")
	s.printHostHighlights(top)
}

func (s *Summary) printPortHighlights(top *client_telemetry.PacketCountSummary) {
	totalTraffic := top.Total.TCPPackets

	// Sort by TCP traffic volume and list in descending order.
	// This is already sorted in TopN but that ordering
	// doesn't seem accessible here.
	ports := make([]int, 0, len(top.TopByPort))
	for p := range top.TopByPort {
		ports = append(ports, p)
	}
	sort.Slice(ports, func(i, j int) bool {
		return top.TopByPort[ports[i]].TCPPackets > top.TopByPort[ports[j]].TCPPackets
	})

	totalListedForPorts := 0
	for i, p := range ports {
		thisPort := top.TopByPort[p]
		pct := thisPort.TCPPackets * 100 / totalTraffic
		totalListedForPorts += thisPort.TCPPackets

		// Stop when the running total would be >100%.  (Each packet is counted both
		// in the source port and in the destination port; we want to avoid
		// showing a bunch of ephemeral ports even if they're all above the threshold.)
		//
		// Before that limit is hit, list at least two sources, but stop when less than 3% of traffic.
		if (totalListedForPorts > totalTraffic) || (pct < 3 && i >= 2) {
			break
		}

		// If we saw any HTTP traffic, report that.  But, if there's a high percentage of unparsed packets, note that too.
		if thisPort.HTTPRequests+thisPort.HTTPResponses > 0 {
			printer.Stderr.Infof("TCP port %5d: %5d packets (%d%% of total), %d HTTP requests, %d HTTP responses, %d TLS handshakes, %d unparsed packets.\n",
				p, thisPort.TCPPackets, pct, thisPort.HTTPRequests, thisPort.HTTPResponses, thisPort.TLSHello, thisPort.Unparsed)
			if thisPort.TLSHello > 0 {
				printer.Stderr.Infof("TCP Port %5d: appears to contain a mix of encrypted and unencrypted traffic.\n", p)
			} else if thisPort.Unparsed > thisPort.TCPPackets*3/10 {
				printer.Stderr.Infof("TCP Port %5d: has an unusually high amount of traffic that Postman cannot parse.\n", p)
			}
			if thisPort.HTTP2Prefaces > 0 {
				printer.Stderr.Infof("TCP Port %5d: Contains HTTP/2 traffic (%d connections detected), which Postman cannot parse.\n", p, thisPort.HTTP2Prefaces)
			}
			continue
		}

		// If we saw HTTP traffic but it was filtered, give the pre-filter statistics
		preFilter := s.PrefilterSummary.TotalOnPort(p)
		if preFilter.HTTPRequests+preFilter.HTTPResponses > 0 {
			printer.Stderr.Infof("TCP port %5d: %5d packets (%d%% of total), no HTTP requests or responses satisfied all the filters you gave, but %d HTTP requests and %d HTTP responses were seen before your path and host filters were applied.\n",
				p, thisPort.TCPPackets, pct, preFilter.HTTPRequests, preFilter.HTTPResponses)
			continue
		}

		// If we saw TLS, report the presence of encrypted traffic
		if thisPort.TLSHello > 0 {
			printer.Stderr.Infof("TCP port %5d: %5d packets (%d%% of total), no HTTP requests or responses, %d TLS handshakes indicating encrypted traffic.\n",
				p, thisPort.TCPPackets, pct, thisPort.TLSHello)
			continue
		}

		// If we saw HTTP/2, report it.
		if thisPort.HTTP2Prefaces > 0 {
			printer.Stderr.Infof("TCP port %5d: %5d packets (%d%% of total), no HTTP/1.1 requests or responses, %d HTTP/2 connection attempts. Postman cannot currently parse HTTP/2.\n",
				p, thisPort.TCPPackets, pct, thisPort.HTTP2Prefaces)
			continue
		}

		// Flag as unparsable
		printer.Stderr.Infof("TCP port %5d: %5d packets (%d%% of total), no HTTP requests or responses; the data to this service could not be parsed.\n",
			p, thisPort.TCPPackets, pct)
	}
}

// XXX(cns): Not all metrics can be associated with a host.  We currently have
//
//	HTTP requests and TLS handshakes.
func (s *Summary) printHostHighlights(top *client_telemetry.PacketCountSummary) {
	// Sort by HTTP traffic volume, then TLS handshake counts, both descending.
	// We do not have TCP packet counts for hosts.
	hosts := make([]string, 0, len(top.TopByHost))
	totalCountForHosts := 0
	for h, c := range top.TopByHost {
		hosts = append(hosts, h)
		totalCountForHosts += c.HTTPRequests + c.HTTPResponses + c.TLSHello
	}
	sort.Slice(hosts, func(i, j int) bool {
		left := top.TopByHost[hosts[i]]
		right := top.TopByHost[hosts[j]]

		leftCount := left.HTTPRequests + left.TLSHello
		rightCount := right.HTTPRequests + right.TLSHello

		if leftCount != rightCount {
			return leftCount > rightCount
		} else if left.HTTPRequests != right.HTTPRequests {
			return left.HTTPRequests > right.HTTPRequests
		} else if left.TLSHello != right.TLSHello {
			return left.TLSHello > right.TLSHello
		} else {
			return hosts[i] < hosts[j]
		}
	})

	// Take up to the first N hosts capturing at least 80% of the data. Until
	// that limit, show at least two hosts but stop when the traffic per host
	// drops below 3%. This avoids a long tail of hosts with very few TLS
	// handshakes.
	printUpTo := 0
	longestHostLength := 0
	countSoFar := 0
	for i, h := range hosts {
		thisHost := top.TopByHost[h]
		thisCount := thisHost.HTTPRequests + thisHost.HTTPResponses + thisHost.TLSHello
		pct := thisCount * 100 / totalCountForHosts
		countSoFar += thisCount
		pctSoFar := countSoFar * 100 / totalCountForHosts

		if 80 < pctSoFar || (pct < 3 && i >= 2) {
			break
		}

		printUpTo = i + 1
		longestHostLength = math.Max(longestHostLength, len(h))
	}

	for _, h := range hosts[:printUpTo] {
		thisHost := top.TopByHost[h]
		labelPreamble := "Host "
		label := fmt.Sprintf("%s%-*s", labelPreamble, longestHostLength, h)
		if h == trace.HostnameUnavailable {
			label = fmt.Sprintf("%-*s", longestHostLength+len(labelPreamble), h)
		}

		// If we saw any HTTP traffic, report that.  But, if there's a high
		// percentage of TLS handshakes, note that too.  Hosts don't have
		// counts for unparsed packets.
		if thisHost.HTTPRequests+thisHost.HTTPResponses > 0 {
			printer.Stderr.Infof("%s %d HTTP requests, %d TLS handshakes.\n",
				label, thisHost.HTTPRequests, thisHost.TLSHello)
			if thisHost.TLSHello > 0 {
				printer.Stderr.Infof("%s appears to contain a mix of encrypted and unencrypted traffic.\n", label)
			}
			continue
		}

		// If we saw HTTP traffic but it was filtered, give the pre-filter statistics.
		preFilter := s.PrefilterSummary.TotalOnHost(h)
		if preFilter.HTTPRequests+preFilter.HTTPResponses > 0 {
			printer.Stderr.Infof("%s no HTTP requests satisfied all the filters you gave, but %d HTTP requests were seen before your path and host filters were applied.\n",
				label, preFilter.HTTPRequests)
			continue
		}

		// If we saw TLS, report the presence of encrypted traffic
		if thisHost.TLSHello > 0 {
			printer.Stderr.Infof("%s no HTTP requests, %d TLS handshakes indicating encrypted traffic.\n",
				label, thisHost.TLSHello)
			continue
		}

		// Flag as unparsable
		printer.Stderr.Infof("%s no HTTP requests or responses; the data to this service could not be parsed.\n",
			label)
	}
}

// Prints warnings based on packet capture behavior, such as not capturing
// any packets, capturing packets but failing to parse them, etc.
func (s *Summary) PrintWarnings() {
	// Report on recoverable error counts during trace
	if pcap.CountNilAssemblerContext > 0 || pcap.CountNilAssemblerContextAfterParse > 0 || pcap.CountBadAssemblerContextType > 0 {
		printer.Stderr.Infof("Detected packet assembly context problems during capture: %v empty, %v bad type, %v empty after parse. ",
			pcap.CountNilAssemblerContext,
			pcap.CountBadAssemblerContextType,
			pcap.CountNilAssemblerContextAfterParse)
		printer.Stderr.Infof("These errors may cause some packets to be missing from the trace.\n")
	}

	// Check summary to see if the trace will have anything in it.
	totalCount := s.FilterSummary.Total()
	if totalCount.HTTPRequests == 0 && totalCount.HTTPResponses == 0 {
		if totalCount.TCPPackets == 0 {
			if s.CapturingNegation && s.NegationSummary.Total().TCPPackets == 0 {
				msg := "Did not capture any TCP packets during the trace. " +
					"This may mean the traffic is on a different interface, or that " +
					"there is a problem sending traffic to the API."
				printer.Stderr.Infof("%s\n", printer.Color.Yellow(msg))
			} else {
				msg := "Did not capture any TCP packets matching the filter. " +
					"This may mean your filter is incorrect, such as the wrong TCP port."
				printer.Stderr.Infof("%s\n", printer.Color.Yellow(msg))
			}
		} else if totalCount.TLSHello > 0 {
			msg := fmt.Sprintf("Captured %d TLS handshake messages out of %d total TCP segments. ", totalCount.TLSHello, totalCount.TCPPackets) +
				"This may mean you are trying to capture HTTPS traffic, which is currently unsupported."
			printer.Stderr.Infof("%s\n", msg)
		} else if totalCount.Unparsed > 0 {
			msg := fmt.Sprintf("Captured %d TCP packets total; %d unparsed TCP segments. ", totalCount.TCPPackets, totalCount.Unparsed) +
				"No TLS headers were found, so this may represent a network protocol that the agent does not know how to parse."
			printer.Stderr.Infof("%s\n", msg)
		} else if s.NumUserFilters > 0 && s.PrefilterSummary.Total().HTTPRequests != 0 {
			printer.Stderr.Infof("Captured %d HTTP requests before allow and exclude rules, but all were filtered.\n",
				s.PrefilterSummary.Total().HTTPRequests)
		}
		if env.InDocker() && env.HasDockerInternalHostAddress() {
			printer.Stderr.Infof("If you're using macOS and your service is not running in a Docker container, try using the native Postman Insights Agent with `brew install postman-insights-agent`.\n")
		}
		printer.Stderr.Errorf("%s 🛑\n\n", printer.Color.Red("No HTTP calls captured!"))
		return
	}
	if totalCount.HTTPRequests == 0 {
		printer.Stderr.Warningf("%s ⚠\n\n", printer.Color.Yellow("Saw HTTP responses, but not requests."))
	}
	if totalCount.HTTPResponses == 0 {
		printer.Stderr.Warningf("%s ⚠\n\n", printer.Color.Yellow("Saw HTTP requests, but not responses."))
	}
}

// Returns true if the trace generated from this apidump will be empty.
func (s *Summary) IsEmpty() bool {
	// Check summary to see if the trace will have anything in it.
	totalCount := s.FilterSummary.Total()
	return totalCount.HTTPRequests == 0 && totalCount.HTTPResponses == 0
}

// DumpPacketCounters prints the accumulated packet counts per interface and per port,
// to the logging function specified in the first argument.
// The "interfaces" argument should be the map keyed by interface names (as created
// in the apidump.Run function); all we really need are those names.
func DumpPacketCounters(logf func(f string, args ...interface{}), interfaces map[string]interfaceInfo, matchedSummary *trace.PacketCounter, unmatchedSummary *trace.PacketCounter, showInterface bool) {
	// Using a map gives inconsistent order when iterating (even on the same run!)
	filterStates := []filterState{matchedFilter, notMatchedFilter}
	toReport := []*trace.PacketCounter{matchedSummary}
	if unmatchedSummary != nil {
		toReport = append(toReport, unmatchedSummary)
	}

	if showInterface {
		logf("========================================================\n")
		logf("Packets per interface:\n")
		logf("%15v %9v %7v %11v %5v %5v\n", "", "", "TCP  ", "HTTP   ", "TLS  ", "")
		logf("%15v %9v %7v %5v %5v %5v %5v\n", "interface", "dir", "packets", "req", "resp", "hello", "unk")
		for n := range interfaces {
			for i, summary := range toReport {
				count := summary.TotalOnInterface(n)
				logf("%15s %9s %7d %5d %5d %5d %5d\n",
					n,
					filterStates[i],
					count.TCPPackets,
					count.HTTPRequests,
					count.HTTPResponses,
					count.TLSHello,
					count.Unparsed,
				)
			}
		}
	}

	logf("========================================================\n")
	logf("Packets per port:\n")
	logf("%8v %7v %11v %5v %5v\n", "", "TCP  ", "HTTP   ", "TLS  ", "")
	logf("%8v %7v %5v %5v %5v %5v\n", "port", "packets", "req", "resp", "hello", "unk")
	for i, summary := range toReport {
		if filterStates[i] == matchedFilter {
			logf("----------- matching filter ------------\n")
		} else {
			logf("--------- not matching filter ----------\n")
		}
		byPort := summary.AllPorts()
		// We don't really know what's in the BPF filter; we know every packet in
		// matchedSummary must have matched, but that could be multiple ports, or
		// some other criteria.
		for _, count := range byPort {
			logf("%8d %7d %5d %5d %5d %5d\n",
				count.SrcPort,
				count.TCPPackets,
				count.HTTPRequests,
				count.HTTPResponses,
				count.TLSHello,
				count.Unparsed,
			)
		}
		if len(byPort) == 0 {
			logf("       no packets captured        \n")
		}
	}

	logf("==================================================\n")

}
