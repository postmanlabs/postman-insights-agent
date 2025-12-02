package daemonset

import (
	"fmt"
	"slices"
	"sync"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/tags"
	"github.com/pkg/errors"
)

type PodTrafficMonitorState string

// Different states of pod traffic monitoring
// The state transition is as follows:
// State diagram: https://whimsical.com/pod-monitoring-state-diagram-Ny5HqFJxz2fntz6ZM6bj2k
const (
	// Pod Lifecycle states
	PodPending       PodTrafficMonitorState = "PodPending"       // When agent will receive pod added event
	PodRunning       PodTrafficMonitorState = "PodRunning"       // When the pod is running and agent can start the apidump process
	PodSucceeded     PodTrafficMonitorState = "PodSucceeded"     // When the pod is terminated successfully, agent will receive pod deleted event
	PodFailed        PodTrafficMonitorState = "PodFailed"        // When the pod is terminated with failure, agent will receive pod deleted event
	PodTerminated    PodTrafficMonitorState = "PodTerminated"    // custom: When the pod is terminated with unknown status
	RemovePodFromMap PodTrafficMonitorState = "RemovePodFromMap" // custom: Final state after which pod will be removed from the map

	// Traffic monitoring states
	TrafficMonitoringRunning PodTrafficMonitorState = "TrafficMonitoringRunning" // When apidump process is running for the pod
	TrafficMonitoringFailed  PodTrafficMonitorState = "TrafficMonitoringFailed"  // When apidump process is errored for the pod
	TrafficMonitoringEnded   PodTrafficMonitorState = "TrafficMonitoringEnded"   // When apidump process is ended without any issue for the pod

	// Daemonset shutdown state
	DaemonSetShutdown PodTrafficMonitorState = "DaemonSetShutdown" // When the daemonset agent starts the shutdown process
)

type PodCreds struct {
	InsightsAPIKey             string
	InsightsEnvironment        string
	InsightsServiceName        string
	InsightsServiceEnvironment string
	InsightsWorkspaceID        string
}

type PodArgs struct {
	// apidump related fields
	InsightsProjectID     akid.ServiceID
	TraceTags             tags.SingletonTags
	ReproMode             bool
	DropNginxTraffic      bool
	AgentRateLimit        float64
	AlwaysCapturePayloads []string

	// Pod related fields
	PodName       string
	ContainerUUID string
	PodCreds      PodCreds

	// for state management
	PodTrafficMonitorState PodTrafficMonitorState
	StateChangeMutex       sync.Mutex `json:"-"`

	// send stop signal to apidump process
	StopChan chan error `json:"-"`
}

func NewPodArgs(podName string) *PodArgs {
	return &PodArgs{
		TraceTags: tags.SingletonTags{},
		PodName:   podName,
		// though 1 buffer size is enough, keeping 2 for safety
		StopChan: make(chan error, 2),
	}
}

// changePodTrafficMonitorState changes the state of the pod traffic monitor to the specified next state.
// It ensures that the current state is one of the allowed states before making the change.
//
// Parameters:
//   - nextState: The desired state to transition to.
//   - allowedCurrentStates: A variadic parameter representing the states from which the transition is allowed.
//
// Returns:
//   - error: An error if the current state is not allowed or if the pod is already in the desired state.
//
// The function locks the state change using a mutex to ensure thread safety.
func (p *PodArgs) changePodTrafficMonitorState(
	nextState PodTrafficMonitorState,
	allowedCurrentStates ...PodTrafficMonitorState,
) error {
	p.StateChangeMutex.Lock()
	defer p.StateChangeMutex.Unlock()

	if isTrafficMonitoringInFinalState(p) {
		return errors.New(fmt.Sprintf("API dump process for pod %s already in final state, state: %s\n", p.PodName, p.PodTrafficMonitorState))
	}

	// Check if the current state is allowed for the transition
	// If the allowedCurrentStates is empty, then any state is allowed
	if len(allowedCurrentStates) != 0 && !slices.Contains(allowedCurrentStates, p.PodTrafficMonitorState) {
		return errors.New(fmt.Sprintf("Invalid current state for pod %s: %s", p.PodName, p.PodTrafficMonitorState))
	}

	if p.PodTrafficMonitorState == nextState {
		return errors.New(fmt.Sprintf("API dump process for pod %s is already in state %s", p.PodName, nextState))
	}

	p.PodTrafficMonitorState = nextState
	return nil
}

// isTrafficMonitoringInFinalState checks if the pod traffic monitor state is in the final state.
func isTrafficMonitoringInFinalState(p *PodArgs) bool {
	switch p.PodTrafficMonitorState {
	case TrafficMonitoringEnded, TrafficMonitoringFailed, RemovePodFromMap:
		return true
	default:
		return false
	}
}

// markAsPruneReady marks the pod as ready to be pruned from the map.
// It ensures that the current state is one of the allowed states before making the change.
func (p *PodArgs) markAsPruneReady() error {
	p.StateChangeMutex.Lock()
	defer p.StateChangeMutex.Unlock()

	switch p.PodTrafficMonitorState {
	case TrafficMonitoringEnded, TrafficMonitoringFailed:
		p.PodTrafficMonitorState = RemovePodFromMap
	case RemovePodFromMap:
		return errors.New(fmt.Sprintf("API dump process for pod %s already in final state, state: %s\n", p.PodName, p.PodTrafficMonitorState))
	default:
		return errors.New(fmt.Sprintf("Invalid state for pod %s: %s\n", p.PodName, p.PodTrafficMonitorState))
	}

	return nil
}
