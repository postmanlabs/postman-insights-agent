package telemetry

import (
	"sync"
	"testing"

	"github.com/akitasoftware/akita-libs/analytics"
)

// The root tracker, behind Default() and the package-level functions, sends
// with the client doInit sets up, as scoped trackers do; with telemetry
// turned off, both send nothing.
func TestRootTrackerUsesTheInitializedClient(t *testing.T) {
	for _, tc := range []struct {
		name     string
		disabled string
		wantNull bool
	}{
		{name: "enabled", disabled: "", wantNull: false},
		{name: "opted out", disabled: "true", wantNull: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// An Amplitude key makes doInit set up a client; the distinct ID
			// gives it a user without calling the Postman API.
			t.Setenv("POSTMAN_INSIGHTS_AGENT_AMPLITUDE_WRITE_KEY", "test-key")
			t.Setenv("POSTMAN_ANALYTICS_DISTINCT_ID", "test-user")
			t.Setenv("AKITA_DISABLE_TELEMETRY", tc.disabled)
			t.Setenv("POSTMAN_INSIGHTS_AGENT_DISABLE_TELEMETRY", "")
			initClientOnce = sync.Once{}
			sharedAnalyticsClient = analytics.NullClient{}
			t.Cleanup(func() {
				_ = sharedAnalyticsClient.Close()
				initClientOnce = sync.Once{}
				sharedAnalyticsClient = analytics.NullClient{}
				rootTracker = nil
				analyticsEnabled = false
			})

			Init(false)

			_, isNull := sharedAnalyticsClient.(analytics.NullClient)
			if isNull != tc.wantNull {
				t.Fatalf("the shared client is %T", sharedAnalyticsClient)
			}
			if rootTracker.analyticsClient != sharedAnalyticsClient {
				t.Errorf("the root tracker sends with %T, not the shared %T", rootTracker.analyticsClient, sharedAnalyticsClient)
			}
			scoped := NewScoped(TrackingUser{UserID: "scoped-user"}).(*trackerImpl)
			if scoped.analyticsClient != sharedAnalyticsClient {
				t.Errorf("a scoped tracker sends with %T, not the shared %T", scoped.analyticsClient, sharedAnalyticsClient)
			}
			if !tc.wantNull && rootTracker.trackingUser.UserID != "test-user" {
				t.Errorf("the root tracker's user is %q", rootTracker.trackingUser.UserID)
			}
		})
	}
}
