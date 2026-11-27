package trace

import (
	"context"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
)

const (
	// How often the agent asks the back end whether this service may capture
	// successful response bodies.
	//
	// Matches the redaction poll: both read the same endpoint, and a service
	// owner switching capture off should see it stop on the same timescale as a
	// redaction taking effect.
	grantPollInterval = time.Minute

	// How long an answer may be trusted once received.
	//
	// Deliberately a small multiple of the poll, not of the grant. The grant
	// lapses server-side, so the agent must stop when it can no longer confirm
	// one -- a partition, a revoked key, a back end that is down -- rather than
	// keep uploading payloads on an answer from an hour ago. Three intervals
	// tolerates a couple of lost polls without reopening that hole.
	grantStaleAfter = 3 * grantPollInterval
)

// GrantSource is the part of rest.LearnClient this poller needs.
type GrantSource interface {
	GetDynamicAgentConfigForService(
		context.Context,
		akid.ServiceID,
	) (*rest.DynamicAgentConfig, error)
}

// PollRecordAllGrant keeps `window` in step with the service owner's setting,
// until `done` is closed.
//
// A failed poll leaves the last answer in place rather than denying outright:
// one timeout should not interrupt a capture someone is watching. What bounds
// that is the staleness deadline carried with each answer, so repeated failures
// shut capture on their own without this loop deciding anything.
//
// An answer of "the back end does not know" (no `record_all` in the response, so
// a nil pointer) is left as no answer at all. The local window then decides, as
// it did before grants existed — otherwise upgrading the agent ahead of the back
// end would silently stop record-all everywhere.
func PollRecordAllGrant(
	client GrantSource,
	serviceID akid.ServiceID,
	window *CaptureWindow,
	done <-chan struct{},
) {
	poll := func() {
		ctx, cancel := context.WithTimeout(context.Background(), grantPollInterval/2)
		defer cancel()

		config, err := client.GetDynamicAgentConfigForService(ctx, serviceID)
		if err != nil {
			printer.Debugf("Could not read the record-all grant for %s: %v\n", akid.String(serviceID), err)

			return
		}

		if config.RecordAll == nil {
			return
		}

		window.SetRemoteGrant(*config.RecordAll, time.Now().Add(grantStaleAfter))
	}

	// Once before the first tick: a capture should not spend a minute uploading
	// successful bodies the owner has not granted, nor a minute refusing ones
	// they have.
	poll()

	go func() {
		ticker := time.NewTicker(grantPollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				poll()
			}
		}
	}()
}
