package telemetry

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/analytics"
	"github.com/akitasoftware/go-utils/maps"
	"github.com/postmanlabs/postman-insights-agent/cfg"
	"github.com/postmanlabs/postman-insights-agent/consts"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/version"
)

const (
	rateLimitDuration = 60 * time.Second
)

var (
	// Global shared analytics client
	sharedAnalyticsClient analytics.Client = analytics.NullClient{}

	// Is analytics enabled?
	analyticsEnabled bool

	// Client key; set at link-time with -X flag
	defaultAmplitudeKey = ""

	serviceIDRegex = regexp.MustCompile(`^svc_[A-Za-z0-9]{22}$`)

	// Timeout talking to API.
	// Shorter than normal because we don't want the CLI to be slow.
	userAPITimeout = 2 * time.Second

	// Sync.once to ensure that client is initialized before trying to use it.
	initClientOnce sync.Once

	// Whether to log client init logs to the console
	isLoggingEnabled bool = true

	// Root tracker instance
	rootTracker *trackerImpl

	// Global rate limit map for backward compatibility
	globalRateLimitMap sync.Map
)

type TrackingUser struct {
	UserID string
	TeamID string
}

type eventRecord struct {
	// Number of events since the last one was sent
	Count int

	// Next time to send an event
	NextSend time.Time
}

// Tracker interface defines the telemetry contract
type Tracker interface {
	// Existing methods (backward compatibility)
	Error(inContext string, e error)
	RateLimitError(inContext string, e error)
	APIError(method string, path string, e error)
	Failure(message string)
	Success(message string)
	WorkflowStep(workflow string, message string)
	CommandLine(command string, commandLine []string)

	// Lifecycle
	Shutdown() error
}

// trackerImpl implements the Tracker interface
type trackerImpl struct {
	analyticsClient analytics.Client
	trackingUser    *TrackingUser
	rateLimitMap    *sync.Map // Per-instance rate limiting
}

// Initialize the telemetry client.
// This should be called once at startup either from the root command
// or from a subcommand that overrides the default PersistentPreRun.
func Init(loggingEnabled bool) {
	isLoggingEnabled = loggingEnabled
	initClientOnce.Do(doInit)
}

func doInit() {
	// Create root tracker instance
	rootTracker = &trackerImpl{
		analyticsClient: sharedAnalyticsClient,
		trackingUser:    &TrackingUser{},
		rateLimitMap:    &globalRateLimitMap,
	}

	// Initialize the base API error handler
	rest.BaseAPIErrorHandler = rootTracker.APIError

	// Opt-out mechanism
	disableTelemetry := os.Getenv("AKITA_DISABLE_TELEMETRY") + os.Getenv("POSTMAN_INSIGHTS_AGENT_DISABLE_TELEMETRY")
	if disableTelemetry != "" {
		if val, err := strconv.ParseBool(disableTelemetry); err == nil && val {
			printer.Infof("Telemetry disabled via opt-out.\n")
			sharedAnalyticsClient = analytics.NullClient{}
			return
		}
	}

	// If unset, will be "" and we'll use the default
	amplitudeEndpoint := os.Getenv("POSTMAN_INSIGHTS_AGENT_AMPLITUDE_ENDPOINT")

	// If unset, will use this hard-coded value.
	amplitudeKey := os.Getenv("POSTMAN_INSIGHTS_AGENT_AMPLITUDE_WRITE_KEY")
	if amplitudeKey == "" {
		amplitudeKey = defaultAmplitudeKey
	}
	if amplitudeKey == "" {
		if isLoggingEnabled {
			printer.Infof("Telemetry unavailable; no Amplitude key configured.\n")
			printer.Infof("This is caused by building from source rather than using an official build.\n")
		}
		sharedAnalyticsClient = analytics.NullClient{}
		return
	}

	var err error
	sharedAnalyticsClient, err = analytics.NewClient(
		analytics.Config{
			// Enable analytics for Amplitude only
			IsAmplitudeEnabled: true,
			AmplitudeConfig: analytics.AmplitudeConfig{
				AmplitudeAPIKey:   amplitudeKey,
				AmplitudeEndpoint: amplitudeEndpoint,
				// No output from the Amplitude library
				IsLoggingEnabled: false,
			},
			App: analytics.AppInfo{
				Name:      "postman-insights-agent",
				Version:   version.ReleaseVersion().String(),
				Build:     version.GitVersion(),
				Namespace: "",
			},
		},
	)
	if err != nil {
		if isLoggingEnabled {
			printer.Infof("Telemetry unavailable; error setting up Analytics(Amplitude) client: %v\n", err)
			printer.Infof("Postman support will not be able to see any errors you encounter.\n")
			printer.Infof("Please send this log message to %s.\n", consts.SupportEmail)
		}
		sharedAnalyticsClient = analytics.NullClient{}
		return
	}

	analyticsEnabled = true

	defaultTrackingUser, err := getUserIdentity() // Initialize user ID and team ID
	if err != nil {
		if isLoggingEnabled {
			printer.Infof("Telemetry unavailable; error getting userID for given API key: %v\n", err)
			printer.Infof("Postman support will not be able to see any errors you encounter.\n")
			printer.Infof("Please send this log message to %s.\n", consts.SupportEmail)
		}
		sharedAnalyticsClient = analytics.NullClient{}
		return
	}
	rootTracker.trackingUser = defaultTrackingUser
}

// Get the tracking user associated with the API key
func GetTrackingUserAssociatedWithAPIKey(frontClient rest.FrontClient) (TrackingUser, error) {
	ctx, cancel := context.WithTimeout(context.Background(), userAPITimeout)
	defer cancel()
	userResponse, err := frontClient.GetUser(ctx)
	if err != nil {
		return TrackingUser{}, err
	}
	return TrackingUser{
		UserID: fmt.Sprint(userResponse.ID),
		TeamID: fmt.Sprint(userResponse.TeamID),
	}, nil
}

func getUserIdentity() (*TrackingUser, error) {
	// If we can get user details use userID and teamID
	// Otherwise use the configured API Key.
	// Failing that, try to use the user name and host name.
	// In latter 2 cases teamID will be empty.

	id := os.Getenv("POSTMAN_ANALYTICS_DISTINCT_ID")
	if id != "" {
		return &TrackingUser{
			UserID: id,
			TeamID: "",
		}, nil
	}

	// If there's no credentials configured, skip the API call and
	// do not emit a log message.
	// Similarly if telemetry is disabled.
	if cfg.CredentialsPresent() && analyticsEnabled {
		// Call the REST API to get the postman user associated with the configured
		// API key.
		frontClient := rest.NewFrontClient(rest.Domain, GetClientID(), nil, nil)
		trackingUser, err := GetTrackingUserAssociatedWithAPIKey(frontClient)
		if err == nil {
			return &trackingUser, nil
		}

		printer.Infof("Telemetry using temporary ID; GetUser API call failed: %v\n", err)
		printer.Infof("This error may indicate a problem communicating with the Postman servers,\n")
		printer.Infof("but the agent will still attempt to send telemetry to Postman support.\n")
	}

	// Try to derive a distinct ID from the credentials, if present, even
	// if the getUser() call failed.
	keyID := cfg.DistinctIDFromCredentials()
	if keyID != "" {
		return &TrackingUser{
			UserID: keyID,
			TeamID: "",
		}, nil
	}

	localUser, err := user.Current()
	if err != nil {
		return &TrackingUser{}, err
	}
	localHost, err := os.Hostname()
	if err != nil {
		return &TrackingUser{
			UserID: localUser.Username,
			TeamID: "",
		}, err
	}
	return &TrackingUser{
		UserID: localUser.Username + "@" + localHost,
		TeamID: "",
	}, nil
}

// Default returns the root tracker instance for backward compatibility
func Default() Tracker {
	initClientOnce.Do(doInit)
	return rootTracker
}

// NewScoped creates a new scoped tracker with different user context
func NewScoped(user TrackingUser) Tracker {
	initClientOnce.Do(doInit)

	return &trackerImpl{
		analyticsClient: sharedAnalyticsClient, // Share the client
		trackingUser:    &user,
		rateLimitMap:    &sync.Map{}, // Each scoped instance gets its own rate limit map
	}
}

// Report an error in a particular operation (inContext), including
// the text of the error.
func (t *trackerImpl) Error(inContext string, e error) {
	t.tryTrackingEvent(
		"Operation - Errored",
		map[string]any{
			"operation": inContext,
			"error":     e.Error(),
		},
	)
}

// Report an error in a particular operation (inContext), including
// the text of the error.  Send only one trace event per minute for
// this particular context; count the remainder.
//
// Rate-limited errors are not flushed when telemetry is shut down.
//
// TODO: consider using the error too, but that could increase
// the cardinality of the map by a lot.
func (t *trackerImpl) RateLimitError(inContext string, e error) {
	newRecord := eventRecord{
		Count:    0,
		NextSend: time.Now().Add(rateLimitDuration),
	}
	existing, present := t.rateLimitMap.LoadOrStore(inContext, newRecord)

	count := 1
	if present {
		record := existing.(eventRecord)

		if record.NextSend.After(time.Now()) {
			// This is a data race but not worth worrying about
			// (by using a mutex); sometimes the count will be low.
			record.Count += 1
			t.rateLimitMap.Store(inContext, record)
			return
		}

		// Time to send a new record, reset the count back to 0 and send
		// the count of the backlog, plus the current event.
		count = record.Count + 1
		t.rateLimitMap.Store(inContext, newRecord)
	}

	t.tryTrackingEvent(
		"Operation - Rate Limited",
		map[string]any{
			"operation": inContext,
			"error":     e.Error(),
			"count":     count,
		},
	)
}

// Report an error in a particular API, including the text of the error.
func (t *trackerImpl) APIError(method string, path string, e error) {
	t.tryTrackingEvent(
		"API Call - Errored",
		map[string]any{
			"method": method,
			"path":   path,
			"error":  e.Error(),
		},
	)
}

// Report a failure without a specific error object
func (t *trackerImpl) Failure(message string) {
	t.tryTrackingEvent(
		"Operation - Errored",
		map[string]any{
			"error": message,
		},
	)
}

// Report success of an operation
func (t *trackerImpl) Success(message string) {
	t.tryTrackingEvent(
		"Operation - Succeeded",
		map[string]any{
			"operation": message,
		},
	)
}

// Report a step in a multi-part workflow.
func (t *trackerImpl) WorkflowStep(workflow string, message string) {
	t.tryTrackingEvent(
		"Workflow Step - Executed",
		map[string]any{
			"step":     message,
			"workflow": workflow,
		},
	)
}

// Report command line flags (before any error checking.)
// This event will be sent before any other events and only once per agent invocation.
func (t *trackerImpl) CommandLine(command string, commandLine []string) {
	// Look for a service ID in the command line
	var serviceID akid.ServiceID
	for _, arg := range commandLine {
		if serviceIDRegex.MatchString(arg) {
			_ = akid.ParseIDAs(arg, &serviceID)
			break
		}
	}

	t.tryTrackingEvent(
		"Command - Executed",
		map[string]any{
			"command":      command,
			"command_line": commandLine,
			"service_id":   serviceID,
		},
	)
}

func (t *trackerImpl) Shutdown() error {
	// Only shutdown the shared client from the root tracker
	if t == rootTracker {
		return t.analyticsClient.Close()
	}
	return nil
}

// Instance-specific tracking event method
func (t *trackerImpl) tryTrackingEvent(eventName string, eventProperties maps.Map[string, any]) {
	eventProperties.Upsert("user_id", t.trackingUser.UserID, func(v, newV any) any { return v })

	if t.trackingUser.TeamID != "" {
		eventProperties.Upsert("team_id", t.trackingUser.TeamID, func(v, newV any) any { return v })
	}

	t.analyticsClient.Track(t.trackingUser.UserID, eventName, eventProperties)
}

// Backward compatibility functions - these delegate to the root tracker
func Error(inContext string, e error) {
	Default().Error(inContext, e)
}

func RateLimitError(inContext string, e error) {
	Default().RateLimitError(inContext, e)
}

func Success(message string) {
	Default().Success(message)
}

func WorkflowStep(workflow string, message string) {
	Default().WorkflowStep(workflow, message)
}

func CommandLine(command string, commandLine []string) {
	Default().CommandLine(command, commandLine)
}

// Flush the telemetry to its endpoint
// (even buffer size of 1 is not enough if the CLI exits right away.)
func Shutdown() {
	if err := Default().Shutdown(); err != nil {
		printer.Stderr.Errorf("Error flushing telemetry: %v\n", err)
		printer.Infof("Postman support may not be able to see the last error message you received.\n")
		printer.Infof("Please send the CLI output to %s.\n", consts.SupportEmail)
	}
}
