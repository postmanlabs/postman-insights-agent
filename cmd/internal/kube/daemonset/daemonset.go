package daemonset

import (
	"context"
	"fmt"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/go-utils/maps"
	"github.com/postmanlabs/postman-insights-agent/apidump"
	"github.com/postmanlabs/postman-insights-agent/cfg"
	"github.com/postmanlabs/postman-insights-agent/integrations/cri_apis"
	"github.com/postmanlabs/postman-insights-agent/integrations/kube_apis"
	"github.com/postmanlabs/postman-insights-agent/printer"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/telemetry"
)

const (
	apiContextTimeout = 20 * time.Second
)

type Args struct {
	ClusterName string
}

type PodCreds struct {
	InsightsAPIKey      string
	InsightsEnvironment string
}

type PodArgs struct {
	// apidump related fields
	InsightsProjectID        akid.ServiceID
	InsightsReproModeEnabled bool

	// Pod related fields
	PodName       string
	ContainerUUID string
}

type Daemonset struct {
	KubeClient kube_apis.KubeClient
	CRIClient  *cri_apis.CriClient

	PodNameStopChanMap maps.Map[string, chan error]
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

func (d *Daemonset) KubernetesEventsWorker() {
	// Not implemented
}

func (d *Daemonset) PodsHealthWorker() {
	// Not implemented
}

func (d *Daemonset) StartApiDumpProcess(podArgs PodArgs, podCreds PodCreds) error {
	networkNamespace, err := d.CRIClient.GetNetworkNamespace(podArgs.ContainerUUID)
	if err != nil {
		return fmt.Errorf("failed to get network namespace: %w", err)
	}

	// Channel to stop the API dump process
	stopChan := make(chan error)

	apidumpArgs := apidump.Args{
		ClientID:               telemetry.GetClientID(),
		Domain:                 rest.Domain,
		ServiceID:              podArgs.InsightsProjectID,
		TargetNetworkNamespace: networkNamespace,
		ReproMode:              podArgs.InsightsReproModeEnabled,
		StopChan:               stopChan,
		PodName:                podArgs.PodName,
	}

	// Put the process stop channel map and start the process in separate go routine
	d.PodNameStopChanMap.Put(podArgs.PodName, stopChan)
	cfg.SetPodPostmanAPIKeyAndEnvironment(podArgs.PodName, podCreds.InsightsAPIKey, podCreds.InsightsEnvironment)
	go func() {
		if err := apidump.Run(apidumpArgs); err != nil {
			printer.Errorf("failed to run API dump process for pod %s: %v", podArgs.PodName, err)
		}
	}()

	return nil
}

func (d *Daemonset) StopApiDumpProcess(podName string, err error) error {
	if stopChan, exists := d.PodNameStopChanMap.Get(podName).Get(); exists {
		printer.Infof("stopping API dump process for pod %s", podName)
		stopChan <- err
		d.PodNameStopChanMap.Delete(podName)
		cfg.UnsetPodPostmanAPIKeyAndEnvironment(podName)
		return nil
	} else {
		printer.Errorf("failed to stop API dump process for pod %s: stop channel not found", podName)
		printer.Errorf("Maybe the pod has already been deleted")
	}
	return nil
}
