package daemonset

import (
	"fmt"
	"slices"
	"sync"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/pkg/errors"
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
	StateChangeMutex       *sync.Mutex

	// send stop signal to apidump process
	StopChan chan error
}

func (p *PodArgs) changePodTrafficMonitorState(
	nextState PodTrafficMonitorState,
	allowedCurrentStates ...PodTrafficMonitorState,
) error {
	p.StateChangeMutex.Lock()
	defer p.StateChangeMutex.Unlock()

	if !slices.Contains(allowedCurrentStates, p.PodTrafficMonitorState) {
		return errors.New(fmt.Sprintf("Invalid current state for pod %s: %d", p.PodName, p.PodTrafficMonitorState))
	}

	if p.PodTrafficMonitorState == nextState {
		return errors.New(fmt.Sprintf("API dump process for pod %s is already in state %d", p.PodName, nextState))
	}

	p.PodTrafficMonitorState = nextState
	return nil
}
