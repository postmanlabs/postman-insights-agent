package kube_apis

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	POD_INFORMER_RESYNC_PERIOD = 10 * time.Minute
	POD_INFORMER_SYNC_TIMEOUT  = 30 * time.Second
)

func newPodInformer(clientset kubernetes.Interface, nodeName string) cache.SharedIndexInformer {
	fieldSelector := fields.OneTermEqualSelector("spec.nodeName", nodeName).String()

	listWatch := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			options.FieldSelector = fieldSelector
			return clientset.CoreV1().Pods("").List(context.Background(), options)
		},

		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			options.FieldSelector = fieldSelector
			return clientset.CoreV1().Pods("").Watch(context.Background(), options)
		},
	}

	return cache.NewSharedIndexInformer(
		listWatch,
		&corev1.Pod{},
		POD_INFORMER_RESYNC_PERIOD,
		cache.Indexers{
			cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
			"uid": func(obj any) ([]string, error) {
				pod, ok := obj.(*corev1.Pod)
				if !ok {
					return nil, fmt.Errorf("expected pod, got %T", obj)
				}
				return []string{string(pod.UID)}, nil
			},
		},
	)
}

func waitForPodInformerSync(informer cache.SharedIndexInformer, timeout time.Duration) error {
	return wait.PollUntilContextTimeout(
		context.Background(),
		100*time.Millisecond,
		timeout,
		true,
		func(context.Context) (bool, error) {
			return informer.HasSynced(), nil
		},
	)
}
