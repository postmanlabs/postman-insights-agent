package pcap

import "testing"

func TestReportPcapCounter(t *testing.T) {
	var event string
	var count uint64
	reportPcapCounter(func(gotEvent string, gotCount uint64) {
		event = gotEvent
		count = gotCount
	}, "pcap_packets_dropped", 17)

	if event != "pcap_packets_dropped" || count != 17 {
		t.Fatalf("reported (%q, %d), want (%q, %d)", event, count, "pcap_packets_dropped", 17)
	}

	reportPcapCounter(func(string, uint64) {
		t.Fatal("zero counter should not be reported")
	}, "pcap_packets_dropped", 0)
}
