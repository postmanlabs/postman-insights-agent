package learn

import (
	"errors"
	"io"
	"strings"

	pb "github.com/akitasoftware/akita-ir/go/api_spec"
	"github.com/akitasoftware/akita-libs/spec_util"
	"github.com/jclem/sseparser"
	"github.com/postmanlabs/postman-insights-agent/printer"
)

// TODO: this function must exist somewhere already
func stringToData(s string) *pb.Data {
	return &pb.Data{Value: &pb.Data_Primitive{Primitive: spec_util.NewPrimitiveString(s)}}
}

// Parse a stream containing a text/event-stream as defined in
// https://html.spec.whatwg.org/multipage/server-sent-events.html
func parseEventStream(stream io.Reader) (*pb.Data, error) {
	scanner := sseparser.NewStreamScanner(stream)

	eventList := &pb.List{}
	for {
		event, _, err := scanner.Next()
		if err != nil {
			if errors.Is(err, sseparser.ErrStreamEOF) {
				break
			}
			return nil, err
		}

		currentStruct := &pb.Struct{
			Fields: map[string]*pb.Data{},
		}
		var data strings.Builder
		// Ignore any comments. Concatenate all data fields with \n.
		// FIXME: it would be nice to test for JSON incrementally with handling
		// the event.  It's not clear we _should_ be attempting to parse JSON
		// that is split over multiple `data` fields.
		for _, e := range event.Fields() {
			switch e.Name {
			case "data":
				if data.Len() > 0 {
					data.WriteString("\n")
				}
				data.WriteString(e.Value)
			case "event", "id", "retry":
				currentStruct.Fields[e.Name] = stringToData(e.Value)
			default:
				printer.Debugf("Unknown field name %q in event stream.\n", e.Name)
			}
		}

		if data.Len() > 0 {
			dataStr := data.String()
			jsonBody, err := parseHTTPBodyJSON(strings.NewReader(dataStr))
			if err != nil {
				currentStruct.Fields["data"] = stringToData(dataStr)
			} else {
				currentStruct.Fields["data"] = jsonBody
			}
		}
		eventList.Elems = append(eventList.Elems, &pb.Data{Value: &pb.Data_Struct{Struct: currentStruct}})
	}
	return &pb.Data{Value: &pb.Data_List{List: eventList}}, nil
}
