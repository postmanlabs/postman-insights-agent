package trace

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/stretchr/testify/assert"
)

type fakeGrantSource struct {
	calls     atomic.Int32
	recordAll *bool
	err       error
}

func (f *fakeGrantSource) GetDynamicAgentConfigForService(
	_ context.Context,
	_ akid.ServiceID,
) (*rest.DynamicAgentConfig, error) {
	f.calls.Add(1)

	if f.err != nil {
		return nil, f.err
	}

	return &rest.DynamicAgentConfig{RecordAll: f.recordAll}, nil
}

func boolPtr(b bool) *bool { return &b }

// The first poll is synchronous, so a capture never spends a poll interval
// uploading successful bodies the owner has not granted -- nor a poll interval
// refusing ones they have.
func TestPollRecordAllGrantAppliesImmediately(t *testing.T) {
	done := make(chan struct{})
	defer close(done)

	granted := &fakeGrantSource{recordAll: boolPtr(true)}
	open := NewCaptureWindow(time.Nanosecond, 0)

	PollRecordAllGrant(granted, akid.GenerateServiceID(), open, done)

	assert.Equal(t, int32(1), granted.calls.Load())
	assert.True(t, open.IsOpen(time.Now()),
		"a granted service captures even where the local window has shut")

	refused := &fakeGrantSource{recordAll: boolPtr(false)}
	closed := NewCaptureWindow(0, 0)

	PollRecordAllGrant(refused, akid.GenerateServiceID(), closed, done)

	assert.False(t, closed.IsOpen(time.Now()),
		"a refusal closes an always-open local window")
}

// Upgrading the agent ahead of the back end must not turn record-all off for
// everyone: a back end that does not answer the question has not said no.
func TestPollRecordAllGrantLeavesUnansweredAlone(t *testing.T) {
	done := make(chan struct{})
	defer close(done)

	silent := &fakeGrantSource{recordAll: nil}
	window := NewCaptureWindow(0, 0)

	PollRecordAllGrant(silent, akid.GenerateServiceID(), window, done)

	assert.True(t, window.IsOpen(time.Now()))
}

// One timeout should not interrupt a capture someone is watching. What bounds
// that is the staleness deadline on the last answer, not this loop.
func TestPollRecordAllGrantKeepsLastAnswerOnError(t *testing.T) {
	done := make(chan struct{})
	defer close(done)

	window := NewCaptureWindow(0, 0)
	window.SetRemoteGrant(true, time.Now().Add(time.Hour))

	failing := &fakeGrantSource{err: errors.New("context deadline exceeded")}
	PollRecordAllGrant(failing, akid.GenerateServiceID(), window, done)

	assert.True(t, window.IsOpen(time.Now()),
		"a failed poll must not be read as a refusal")
}
