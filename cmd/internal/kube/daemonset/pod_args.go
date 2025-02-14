package daemonset

import (
	"fmt"
	"slices"
	"sync"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/pkg/errors"
)

type PodTrafficMonitorState string

// Different states of pod traffic monitoring
// The state transition is as follows:
// PodDetected/PodInitialized -> TrafficMonitoringStarted -> TrafficMonitoringFailed/TrafficMonitoringEnded/PodTerminated -> TrafficMonitoringStopped -> RemovePodFromMap
// 'DaemonSetShutdown' is a special state which is used to stop the daemonset agent and can be triggered at any time
const (
	PodDetected              PodTrafficMonitorState = "PodDetected"              // When agent finds an already running pod
	PodInitialized           PodTrafficMonitorState = "PodInitialized"           // When agent will receive pod created event
	TrafficMonitoringStarted PodTrafficMonitorState = "TrafficMonitoringStarted" // When apidump process is started for the pod
	TrafficMonitoringFailed  PodTrafficMonitorState = "TrafficMonitoringFailed"  // When apidump process is errored for the pod
	TrafficMonitoringEnded   PodTrafficMonitorState = "TrafficMonitoringEnded"   // When apidump process is ended without any issue for the pod
	PodTerminated            PodTrafficMonitorState = "PodTerminated"            // When agent will receive pod deleted event or pod is in terminal state while checking status
	DaemonSetShutdown        PodTrafficMonitorState = "DaemonSetShutdown"        // When the daemonset agent starts the shutdown process
	TrafficMonitoringStopped PodTrafficMonitorState = "TrafficMonitoringStopped" // When apidump process is stopped for the pod
	RemovePodFromMap         PodTrafficMonitorState = "RemovePodFromMap"         // Final state after which pod will be removed from the map
)

type PodCreds struct {
	InsightsAPIKey      string
	InsightsEnvironment string
}

type PodArgs struct {
	// apidump related fields
	InsightsProjectID akid.ServiceID

	// Pod related fields
	PodName       string
	ContainerUUID string
	PodCreds      PodCreds

	// for state management
	PodTrafficMonitorState PodTrafficMonitorState
	StateChangeMutex       sync.Mutex

	// send stop signal to apidump process
	StopChan chan error
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

	if !slices.Contains(allowedCurrentStates, p.PodTrafficMonitorState) {
		return errors.New(fmt.Sprintf("Invalid current state for pod %s: %s", p.PodName, p.PodTrafficMonitorState))
	}

	if p.PodTrafficMonitorState == nextState {
		return errors.New(fmt.Sprintf("API dump process for pod %s is already in state %s", p.PodName, nextState))
	}

	p.PodTrafficMonitorState = nextState
	return nil
}
