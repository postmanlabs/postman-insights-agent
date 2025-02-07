package daemonset

import (
	"context"
	"fmt"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/integrations/cri_apis"
	"github.com/postmanlabs/postman-insights-agent/integrations/kube_apis"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
	coreV1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"
)

const (
	apiContextTimeout = 20 * time.Second
)

type Args struct {
	ClusterName string
}

type ApidumpArgs struct {
	InsightsProjectID akid.ServiceID
	InsightsAPIKey    string
}

type Daemonset struct {
	KubeClient kube_apis.KubeClient
	CRIClient  *cri_apis.CriClient
}

func StartDaemonset(args Args) error {
	frontClient := rest.NewFrontClient(rest.Domain, telemetry.GetClientID())
	ctx, cancel := context.WithTimeout(context.Background(), apiContextTimeout)
	defer cancel()

	// Send initial telemetry
	err := frontClient.PostDaemonsetAgentTelemetry(ctx, args.ClusterName)
	if err != nil {
		return err
	}

	kubeClient, err := kube_apis.NewKubeClient()
	if err != nil {
		return fmt.Errorf("failed to create kube client: %w", err)
	}

	criClient, err := cri_apis.NewCRIClient("")
	if err != nil {
		return fmt.Errorf("failed to create CRI client: %w", err)
	}

	errChan := make(chan error)
	go func() {
		daemonsetRun := &Daemonset{
			KubeClient: kubeClient,
			CRIClient:  criClient,
		}
		errChan <- daemonsetRun.Run()
	}()

	return <-errChan
}

func (d *Daemonset) Run() error {
	return fmt.Errorf("not implemented")
}

func (d *Daemonset) TelemetryWorker() {
	// Not implemented
}

func (d *Daemonset) StartProcessInExistingPods() error {
	return fmt.Errorf("not implemented")
}

func (d *Daemonset) KubernetesEventsWorker(done chan struct{}) {
	for {
		select {
		case <-done:
			return
		case event := <-d.KubeClient.EventWatch.ResultChan():
			switch event.Type {
			case watch.Added:
				if e, ok := event.Object.(*coreV1.Event); ok {
					pods, err := d.KubeClient.GetPods([]string{e.InvolvedObject.Name})
					if err != nil {
						printer.Errorf("failed to get pod for k8s added event, pod name: %s, error: %v", e.InvolvedObject.Name, err)
					}
					if len(pods) == 0 {
						printer.Errorf("no pods found for k8s added event, pod name: %s", e.InvolvedObject.Name)
					}

					apidumpArgs, err := d.inspectPodForEnvVars(pods[0])
					if err != nil {
						printer.Errorf("failed to inspect pod for env vars, pod name: %s, error: %v", e.InvolvedObject.Name, err)
					}

					err = d.StartApiDumpProcess(apidumpArgs)
					if err != nil {
						printer.Errorf("failed to start api dump process, pod name: %s, error: %v", e.InvolvedObject.Name, err)
					}
				}
			case watch.Deleted:
				if e, ok := event.Object.(*coreV1.Event); ok {
					go d.StopApiDumpProcess(e.InvolvedObject.Name)
				}
			}
		}
	}
}

func (d *Daemonset) PodsHealthWorker() {
	// Not implemented
}

func (d *Daemonset) StartApiDumpProcess(args ApidumpArgs) error {
	return fmt.Errorf("not implemented")
}

func (d *Daemonset) StopApiDumpProcess(podName string) error {
	return fmt.Errorf("not implemented")
}

func (d *Daemonset) inspectPodForEnvVars(pod coreV1.Pod) (ApidumpArgs, error) {
	// Get the UUID of the main container in the pod
	containerUUID, err := d.KubeClient.GetMainContainerUUID(pod)
	if err != nil {
		return ApidumpArgs{}, fmt.Errorf("failed to get main container UUID: %w", err)
	}

	// Get the environment variables of the main container
	envVars, err := d.CRIClient.GetEnvVars(containerUUID)
	if err != nil {
		return ApidumpArgs{}, fmt.Errorf("failed to get environment variables for container %s: %w", containerUUID, err)
	}

	var (
		insightsProjectID akid.ServiceID
		insightsAPIKey    string
	)

	// Extract the necessary environment variables
	for key, value := range envVars {
		if key == "POSTMAN_INSIGHTS_PROJECT_ID" {
			err := akid.ParseIDAs(value, &insightsProjectID)
			if err != nil {
				return ApidumpArgs{}, errors.Wrap(err, "failed to parse project ID")
			}
		} else if key == "POSTMAN_INSIGHTS_API_KEY" {
			insightsAPIKey = value
		}
	}

	return ApidumpArgs{insightsProjectID, insightsAPIKey}, nil
}
