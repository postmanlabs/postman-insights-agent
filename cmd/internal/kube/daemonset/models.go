package daemonset

import (
	"fmt"
	"slices"
	"sync"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/printer"
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
	PodTrafficMonitorStage PodTrafficMonitorStage
	StageChangeMutex       *sync.Mutex

	// send stop signal to apidump process
	StopChan chan error
}

func (p *PodArgs) setPodTrafficMonitorStage(stage PodTrafficMonitorStage) {
	p.StageChangeMutex.Lock()
	defer p.StageChangeMutex.Unlock()
	p.PodTrafficMonitorStage = stage
}

func (p *PodArgs) validatePodTrafficMonitorStage(
	nextStage PodTrafficMonitorStage,
	allowedPriorStages ...PodTrafficMonitorStage,
) (bool, error) {
	if slices.Contains(allowedPriorStages, p.PodTrafficMonitorStage) {
		return false, nil
	}

	if p.PodTrafficMonitorStage == nextStage {
		printer.Debugf("API dump process for pod %s is already in state %d", p.PodName, nextStage)
		return true, nil
	}

	return false, errors.New(fmt.Sprintf("Invalid prior state for pod %s: %d", p.PodName,
		p.PodTrafficMonitorStage))
}
