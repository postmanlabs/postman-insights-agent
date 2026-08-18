package kube_apis

import (
	"context"
	"errors"
	"testing"
	"time"

	coreV1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

func TestPodInformerPopulatesCacheAndUIDIndex(t *testing.T) {
	pod := &coreV1.Pod{
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "pod-a",
			Namespace: "default",
			UID:       types.UID("pod-a-uid"),
		},
		Spec: coreV1.PodSpec{NodeName: "node-a"},
	}
	clientset := fake.NewSimpleClientset(pod)
	informer := newPodInformer(clientset, "node-a")
	stopCh := make(chan struct{})
	defer close(stopCh)
	go informer.Run(stopCh)

	if err := waitForPodInformerSync(informer, POD_INFORMER_SYNC_TIMEOUT); err != nil {
		t.Fatalf("pod informer did not sync: %v", err)
	}

	kubeClient := KubeClient{PodInformer: informer}
	pods, err := kubeClient.GetPodsInAgentNode()
	if err != nil {
		t.Fatalf("GetPodsInAgentNode() returned error: %v", err)
	}
	if len(pods) != 1 || pods[0].UID != pod.UID {
		t.Fatalf("GetPodsInAgentNode() = %v, want pod %s", pods, pod.UID)
	}

	pods, err = kubeClient.GetPodsByUIDs([]types.UID{pod.UID})
	if err != nil {
		t.Fatalf("GetPodsByUIDs() returned error: %v", err)
	}
	if len(pods) != 1 || pods[0].Name != pod.Name {
		t.Fatalf("GetPodsByUIDs() = %v, want pod %s", pods, pod.Name)
	}
}

func TestPodInformerDeliversAddEvent(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	informer := newPodInformer(clientset, "node-a")
	stopCh := make(chan struct{})
	defer close(stopCh)
	added := make(chan struct{}, 1)
	_, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(interface{}) { added <- struct{}{} },
	})
	if err != nil {
		t.Fatalf("AddEventHandler() returned error: %v", err)
	}
	go informer.Run(stopCh)
	if err := waitForPodInformerSync(informer, POD_INFORMER_SYNC_TIMEOUT); err != nil {
		t.Fatalf("pod informer did not sync: %v", err)
	}

	pod := &coreV1.Pod{
		ObjectMeta: metaV1.ObjectMeta{Name: "pod-a", Namespace: "default", UID: types.UID("pod-a-uid")},
		Spec:       coreV1.PodSpec{NodeName: "node-a"},
	}
	if _, err := clientset.CoreV1().Pods("default").Create(t.Context(), pod, metaV1.CreateOptions{}); err != nil {
		t.Fatalf("create pod: %v", err)
	}

	select {
	case <-added:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for pod add event")
	}
}

func TestPodInformerSyncTimesOut(t *testing.T) {
	informer := newPodInformer(fake.NewSimpleClientset(), "node-a")

	err := waitForPodInformerSync(informer, 10*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waitForPodInformerSync() error = %v, want context deadline exceeded", err)
	}
}
