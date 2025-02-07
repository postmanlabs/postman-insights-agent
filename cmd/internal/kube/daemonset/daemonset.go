package daemonset

import (
	"context"
	"fmt"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/postmanlabs/postman-insights-agent/apispec"
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

type ApidumpArgs struct {
	InsightsProjectID akid.ServiceID
	InsightsAPIKey    string
}

type Daemonset struct {
	ClusterName string

	KubeClient  kube_apis.KubeClient
	CRIClient   *cri_apis.CriClient
	FrontClient rest.FrontClient

	TelemetryInterval time.Duration
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
			ClusterName:       args.ClusterName,
			KubeClient:        kubeClient,
			CRIClient:         criClient,
			FrontClient:       frontClient,
			TelemetryInterval: apispec.DefaultTelemetryInterval_seconds * time.Second, // Is 5 min okay or it should be less?
		}
		errChan <- daemonsetRun.Run()
	}()

	return <-errChan
}

func (d *Daemonset) Run() error {
	return fmt.Errorf("not implemented")
}

func (d *Daemonset) sendTelemetry() {
	ctx, cancel := context.WithTimeout(context.Background(), apiContextTimeout)
	defer cancel()

	err := d.FrontClient.PostDaemonsetAgentTelemetry(ctx, d.ClusterName)
	if err != nil {
		printer.Errorf("Failed to send telemetry: %v\n", err)
	}
}

func (d *Daemonset) TelemetryWorker(done <-chan struct{}) {
	if d.TelemetryInterval <= 0 {
		return
	}

	ticker := time.NewTicker(d.TelemetryInterval)

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			d.sendTelemetry()
		}
	}
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

func (d *Daemonset) StartApiDumpProcess(args ApidumpArgs) error {
	return fmt.Errorf("not implemented")
}

func (d *Daemonset) StopApiDumpProcess() error {
	return fmt.Errorf("not implemented")
}
