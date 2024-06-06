package trace

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/tags"
	"github.com/google/martian/v3/har"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/learn"
	"github.com/postmanlabs/postman-insights-agent/version"
)

type HARCollector struct {
	logger        *har.Logger
	interfaceName string
	outDir        string

	tags map[tags.Key]string
}

func NewHARCollector(interfaceName, outDir string, tags map[tags.Key]string) *HARCollector {
	return &HARCollector{
		logger:        har.NewLogger(),
		interfaceName: interfaceName,
		outDir:        outDir,
		tags:          tags,
	}
}

func (h *HARCollector) Process(t akinet.ParsedNetworkTraffic) error {
	switch c := t.Content.(type) {
	case akinet.HTTPRequest:
		id := learn.ToWitnessID(c.StreamID, c.Seq)
		h.logger.RecordRequestWithTimestamps(akid.String(id), c.ToStdRequest(),
			&har.MessageTimestamps{
				StartTime: t.ObservationTime,
				EndTime:   t.FinalPacketTime,
			},
		)
	case akinet.HTTPResponse:
		id := learn.ToWitnessID(c.StreamID, c.Seq)
		h.logger.RecordResponseWithTimestamps(akid.String(id), c.ToStdResponse(),
			&har.MessageTimestamps{
				StartTime: t.ObservationTime,
				EndTime:   t.FinalPacketTime,
			},
		)
	}
	return nil
}

// TODO: output HAR files periodically instead of buffering everything in
// memory.
func (h *HARCollector) Close() error {
	harContent := h.logger.ExportAndReset()

	// Record AkitaExtension
	harContent.AkitaExt = har.AkitaExtension{
		Outbound: false,
		Tags:     h.tags,
	}

	if log := harContent.Log; log != nil {
		if len(log.Entries) == 0 {
			// No need to write an empty file.
			return nil
		}

		// Customize the creator info.
		log.Creator = &har.Creator{
			Name:    "Akita SuperLearn (https://akitasoftware.com)",
			Version: version.CLIDisplayString(),
		}
	} else {
		// No need to write an empty file.
		return nil
	}

	harBytes, err := json.Marshal(harContent)
	if err != nil {
		return errors.Wrap(err, "failed to marshal HAR to JSON")
	}

	outPath := path.Join(h.outDir, fmt.Sprintf("akita_%s.har", h.interfaceName))
	if err := ioutil.WriteFile(outPath, harBytes, 0644); err != nil {
		return errors.Wrap(err, "failed to write HAR file")
	}
	return nil
}
