package daemonset

import (
	"context"
	"testing"
	"time"

	"github.com/postmanlabs/postman-insights-agent/integrations/kube_apis"
	"github.com/stretchr/testify/require"
	coreV1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

type podInformerTestEnv struct {
	clientset *fake.Clientset
	informer  cache.SharedIndexInformer
	stopCh    chan struct{}
}

func newPodInformerTestEnv(t *testing.T, pods ...*coreV1.Pod) podInformerTestEnv {
	t.Helper()
	clientset := fake.NewSimpleClientset()
	for _, pod := range pods {
		_, err := clientset.CoreV1().Pods(pod.Namespace).Create(
			t.Context(), pod, metaV1.CreateOptions{},
		)
		require.NoError(t, err)
	}

	informer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metaV1.ListOptions) (runtime.Object, error) {
				return clientset.CoreV1().Pods("").List(context.Background(), options)
			},
			WatchFunc: func(options metaV1.ListOptions) (watch.Interface, error) {
				return clientset.CoreV1().Pods("").Watch(context.Background(), options)
			},
		},
		&coreV1.Pod{},
		0,
		cache.Indexers{},
	)
	stopCh := make(chan struct{})
	go informer.Run(stopCh)
	if !cache.WaitForCacheSync(stopCh, informer.HasSynced) {
		t.Fatal("pod informer did not sync")
	}
	t.Cleanup(func() { close(stopCh) })

	return podInformerTestEnv{clientset: clientset, informer: informer, stopCh: stopCh}
}

func testDaemonsetForInformer(informer cache.SharedIndexInformer) *Daemonset {
	return &Daemonset{
		KubeClient: kube_apis.KubeClient{PodInformer: informer},
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}

func TestRegisterPodEventHandlersHandlesAdd(t *testing.T) {
	env := newPodInformerTestEnv(t)
	d := testDaemonsetForInformer(env.informer)
	require.NoError(t, d.registerPodEventHandlers(env.stopCh))

	pod := &coreV1.Pod{
		ObjectMeta: metaV1.ObjectMeta{Namespace: "default", Name: "pod-a", UID: "pod-a-uid"},
		Spec:       coreV1.PodSpec{Containers: []coreV1.Container{{Name: "app", Image: "example/app:latest"}}},
	}
	_, err := env.clientset.CoreV1().Pods("default").Create(t.Context(), pod, metaV1.CreateOptions{})
	require.NoError(t, err)

	waitFor(t, func() bool {
		_, ok := d.PodArgsByNameMap.Load(pod.UID)
		return ok
	})
}

func TestPodEventDispatcherPreservesLifecycleOrder(t *testing.T) {
	d := &Daemonset{}
	dispatcher := newPodEventDispatcher()
	dispatcher.start(d)

	pod := coreV1.Pod{
		ObjectMeta: metaV1.ObjectMeta{Namespace: "default", Name: "pod-a", UID: "pod-a-uid"},
		Spec:       coreV1.PodSpec{Containers: []coreV1.Container{{Name: "app", Image: "example/app:latest"}}},
	}
	runningPod := *pod.DeepCopy()
	runningPod.Status.Phase = coreV1.PodRunning
	dispatcher.enqueue(&podEvent{eventType: podAdded, pod: pod})
	dispatcher.enqueue(&podEvent{eventType: podModified, pod: runningPod})
	dispatcher.stop()

	if _, ok := d.PodArgsByNameMap.Load(pod.UID); ok {
		t.Fatal("Update ran before Add and left the pod in Pending state")
	}
}

func TestHandlePodAddEventIsIdempotentForReplayedRunningPod(t *testing.T) {
	env := newPodInformerTestEnv(t)
	d := testDaemonsetForInformer(env.informer)
	pod := coreV1.Pod{
		ObjectMeta: metaV1.ObjectMeta{Namespace: "default", Name: "pod-a", UID: "pod-a-uid"},
		Spec:       coreV1.PodSpec{Containers: []coreV1.Container{{Name: "app", Image: "example/app:latest"}}},
		Status:     coreV1.PodStatus{Phase: coreV1.PodRunning},
	}
	existing := NewPodArgs(pod.Name)
	require.NoError(t, existing.changePodTrafficMonitorState(PodRunning))
	d.PodArgsByNameMap.Store(pod.UID, existing)

	d.handlePodAddEvent(pod)

	actual, err := d.getPodArgsFromMap(pod.UID)
	require.NoError(t, err)
	if actual != existing {
		t.Fatal("replayed Add replaced the existing pod state")
	}
	if actual.PodTrafficMonitorState != PodRunning {
		t.Fatalf("replayed Add changed state to %s, want %s", actual.PodTrafficMonitorState, PodRunning)
	}
}

func TestHandlePodAddEventProcessesNewRunningPod(t *testing.T) {
	env := newPodInformerTestEnv(t)
	d := testDaemonsetForInformer(env.informer)
	pod := coreV1.Pod{
		ObjectMeta: metaV1.ObjectMeta{Namespace: "default", Name: "pod-a", UID: "pod-a-uid"},
		Spec:       coreV1.PodSpec{Containers: []coreV1.Container{{Name: "app", Image: "example/app:latest"}}},
		Status:     coreV1.PodStatus{Phase: coreV1.PodRunning},
	}

	d.handlePodAddEvent(pod)

	// The pod has no container statuses, so Modify reaches the existing
	// inspection failure path and removes the temporary Pending entry. If Add
	// did not dispatch the Running pod through Modify, it would remain Pending.
	if _, ok := d.PodArgsByNameMap.Load(pod.UID); ok {
		t.Fatal("new Running pod remained in the map after Add handling")
	}
}

func TestRegisterPodEventHandlersReplaysExistingRunningPodSafely(t *testing.T) {
	pod := &coreV1.Pod{
		ObjectMeta: metaV1.ObjectMeta{Namespace: "default", Name: "pod-a", UID: "pod-a-uid"},
		Status:     coreV1.PodStatus{Phase: coreV1.PodRunning},
	}
	env := newPodInformerTestEnv(t, pod)
	d := testDaemonsetForInformer(env.informer)
	existing := NewPodArgs(pod.Name)
	require.NoError(t, existing.changePodTrafficMonitorState(PodRunning))
	d.PodArgsByNameMap.Store(pod.UID, existing)

	require.NoError(t, d.registerPodEventHandlers(env.stopCh))
	waitFor(t, func() bool {
		actual, err := d.getPodArgsFromMap(pod.UID)
		return err == nil && actual == existing && actual.PodTrafficMonitorState == PodRunning
	})
}

func TestRegisterPodEventHandlersHandlesUpdate(t *testing.T) {
	pod := &coreV1.Pod{
		ObjectMeta: metaV1.ObjectMeta{Namespace: "default", Name: "pod-a", UID: "pod-a-uid"},
		Spec:       coreV1.PodSpec{Containers: []coreV1.Container{{Name: "app", Image: "example/app:latest"}}},
	}
	env := newPodInformerTestEnv(t, pod)
	d := testDaemonsetForInformer(env.informer)
	require.NoError(t, d.registerPodEventHandlers(env.stopCh))

	waitFor(t, func() bool {
		_, ok := d.PodArgsByNameMap.Load(pod.UID)
		return ok
	})

	updated := pod.DeepCopy()
	updated.Status.Phase = coreV1.PodRunning
	_, err := env.clientset.CoreV1().Pods("default").Update(t.Context(), updated, metaV1.UpdateOptions{})
	require.NoError(t, err)

	// The test pod has no container statuses, so the existing Modify handler
	// removes it when inspection cannot find a running container.
	waitFor(t, func() bool {
		_, ok := d.PodArgsByNameMap.Load(pod.UID)
		return !ok
	})
}

func TestRegisterPodEventHandlersHandlesDelete(t *testing.T) {
	env := newPodInformerTestEnv(t)
	d := testDaemonsetForInformer(env.informer)
	require.NoError(t, d.registerPodEventHandlers(env.stopCh))

	pod := &coreV1.Pod{
		ObjectMeta: metaV1.ObjectMeta{Namespace: "default", Name: "pod-a", UID: "pod-a-uid"},
		Status:     coreV1.PodStatus{Phase: coreV1.PodSucceeded},
	}
	args := NewPodArgs(pod.Name)
	require.NoError(t, args.changePodTrafficMonitorState(TrafficMonitoringRunning))
	d.PodArgsByNameMap.Store(pod.UID, args)
	_, err := env.clientset.CoreV1().Pods("default").Create(t.Context(), pod, metaV1.CreateOptions{})
	require.NoError(t, err)
	err = env.clientset.CoreV1().Pods("default").Delete(t.Context(), pod.Name, metaV1.DeleteOptions{})
	require.NoError(t, err)

	waitFor(t, func() bool { return args.PodTrafficMonitorState == PodSucceeded })
	select {
	case <-args.StopChan:
	case <-time.After(2 * time.Second):
		t.Fatal("delete handler did not signal the apidump process")
	}
}

func TestPodFromDeleteEventHandlesTombstones(t *testing.T) {
	pod := &coreV1.Pod{}
	for _, object := range []interface{}{
		cache.DeletedFinalStateUnknown{Key: "default/pod-a", Obj: pod},
		&cache.DeletedFinalStateUnknown{Key: "default/pod-a", Obj: pod},
	} {
		actual, ok := podFromDeleteEvent(object)
		if !ok || actual != pod {
			t.Fatalf("podFromDeleteEvent(%T) = %v, %v", object, actual, ok)
		}
	}
}

func TestReconcileMissingPodsAfterStartupTerminatesMissingPod(t *testing.T) {
	pod := &coreV1.Pod{
		ObjectMeta: metaV1.ObjectMeta{Namespace: "default", Name: "pod-a", UID: "pod-a-uid"},
	}
	env := newPodInformerTestEnv(t, pod)
	d := testDaemonsetForInformer(env.informer)
	args := NewPodArgs("pod-a")
	require.NoError(t, args.changePodTrafficMonitorState(TrafficMonitoringRunning))
	d.PodArgsByNameMap.Store(pod.UID, args)

	err := env.clientset.CoreV1().Pods("default").Delete(t.Context(), pod.Name, metaV1.DeleteOptions{})
	require.NoError(t, err)
	waitFor(t, func() bool {
		_, exists, err := env.informer.GetStore().Get(pod)
		return err == nil && !exists
	})

	require.NoError(t, d.reconcileMissingPodsAfterStartup())

	if args.PodTrafficMonitorState != PodTerminated {
		t.Fatalf("pod state = %s, want %s", args.PodTrafficMonitorState, PodTerminated)
	}
	select {
	case <-args.StopChan:
	case <-time.After(2 * time.Second):
		t.Fatal("missing pod was not signaled to stop")
	}
}

func TestReconcileMissingPodsAfterStartupKeepsCachedPod(t *testing.T) {
	pod := &coreV1.Pod{
		ObjectMeta: metaV1.ObjectMeta{Namespace: "default", Name: "pod-a", UID: "pod-a-uid"},
	}
	env := newPodInformerTestEnv(t, pod)
	d := testDaemonsetForInformer(env.informer)
	args := NewPodArgs(pod.Name)
	require.NoError(t, args.changePodTrafficMonitorState(TrafficMonitoringRunning))
	d.PodArgsByNameMap.Store(pod.UID, args)

	require.NoError(t, d.reconcileMissingPodsAfterStartup())

	if args.PodTrafficMonitorState != TrafficMonitoringRunning {
		t.Fatalf("cached pod state = %s, want %s", args.PodTrafficMonitorState, TrafficMonitoringRunning)
	}
	select {
	case <-args.StopChan:
		t.Fatal("cached pod was incorrectly signaled to stop")
	default:
	}
}
