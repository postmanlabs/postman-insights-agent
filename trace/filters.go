package trace

import (
	"regexp"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/trackers"
	"github.com/postmanlabs/postman-insights-agent/capturestats"
	"github.com/postmanlabs/postman-insights-agent/learn"
)

// Filters out HTTP paths.
// TODO: compile the N regular expressions into one for efficiency.
func NewHTTPPathFilterCollector(matchers []*regexp.Regexp, col Collector, stats *capturestats.Stats) Collector {
	return &genericRequestFilter{
		Collector: col,
		filterFunc: func(r akinet.HTTPRequest) bool {
			if r.URL != nil {
				for _, m := range matchers {
					if m.MatchString(r.URL.Path) {
						return false
					}
				}
			}
			return true
		},
		stats: stats,
	}
}

// Filter out matching HTTP hosts
func NewHTTPHostFilterCollector(matchers []*regexp.Regexp, col Collector, stats *capturestats.Stats) Collector {
	return &genericRequestFilter{
		Collector: col,
		filterFunc: func(r akinet.HTTPRequest) bool {
			for _, m := range matchers {
				if m.MatchString(r.Host) {
					return false
				}
			}
			return true
		},
		stats: stats,
	}
}

// Allows only matching paths
// TODO: compile the N regular expressions into one for efficiency.
func NewHTTPPathAllowlistCollector(matchers []*regexp.Regexp, col Collector, stats *capturestats.Stats) Collector {
	return &genericRequestFilter{
		Collector: col,
		filterFunc: func(r akinet.HTTPRequest) bool {
			if r.URL != nil {
				for _, m := range matchers {
					if m.MatchString(r.URL.Path) {
						return true
					}
				}
			}
			return false
		},
		stats: stats,
	}
}

// Allows only matching hosts
func NewHTTPHostAllowlistCollector(matchers []*regexp.Regexp, col Collector, stats *capturestats.Stats) Collector {
	return &genericRequestFilter{
		Collector: col,
		filterFunc: func(r akinet.HTTPRequest) bool {
			for _, m := range matchers {
				if m.MatchString(r.Host) {
					return true
				}
			}
			return false
		},
		stats: stats,
	}
}

// Filters out third-party trackers.
func New3PTrackerFilterCollector(col Collector) Collector {
	return &genericRequestFilter{
		Collector: col,
		filterFunc: func(r akinet.HTTPRequest) bool {
			if r.URL != nil {
				return !trackers.IsTrackerDomain(r.URL.Host)
			}
			return true
		},
	}
}

// Generic filter collector to filter out requests that match a custom filter
// function. Handles filtering out the corresponding responses as well.
type genericRequestFilter struct {
	Collector Collector

	// Returns true if the request should be included.
	filterFunc func(akinet.HTTPRequest) bool

	// Records witness IDs of filtered requests so we can filter out the
	// corresponding responses.
	// NOTE: we're assuming that we always see the request before the
	// corresponding response, which should be generally true, with the exception
	// of observing a response without request due to packet capture starting
	// mid-connection.
	filteredIDs map[akid.WitnessID]struct{}

	// Filtered traffic is counted, not reported per message. A broad host or
	// path filter can exclude nearly every message on the interface, and one
	// telemetry event per drop would take the DaemonSet's node-wide telemetry
	// lock that many times, on the capture path. The counters ship as
	// interval deltas instead -- see apidump.reportSourceFunnel.
	stats *capturestats.Stats
}

func (fc *genericRequestFilter) Process(t akinet.ParsedNetworkTraffic) error {
	include := true
	switch c := t.Content.(type) {
	case akinet.HTTPRequest:
		if fc.filterFunc != nil && !fc.filterFunc(c) {
			include = false
			fc.stats.IncrRequestsFiltered()

			if fc.filteredIDs == nil {
				fc.filteredIDs = map[akid.WitnessID]struct{}{}
			}
			fc.filteredIDs[learn.ToWitnessID(c.StreamID, c.Seq)] = struct{}{}
		}
	case akinet.HTTPResponse:
		if _, ok := fc.filteredIDs[learn.ToWitnessID(c.StreamID, c.Seq)]; ok {
			include = false
			fc.stats.IncrResponsesFiltered()
		}
	}

	if include {
		return fc.Collector.Process(t)
	}
	return nil
}

func (fc *genericRequestFilter) Close() error {
	return fc.Collector.Close()
}
