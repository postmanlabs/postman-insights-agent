package injector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func Test_Inject(t *testing.T) {
	toUnstructured := func(obj runtime.Object) *unstructured.Unstructured {
		u, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&obj)
		if err != nil {
			panic(err)
		}

		return &unstructured.Unstructured{Object: u}
	}

	appendContainer := func(deployment *appsv1.Deployment, container v1.Container) *appsv1.Deployment {
		injectedDeployment := deployment.DeepCopy()
		containers := injectedDeployment.Spec.Template.Spec.Containers
		injectedDeployment.Spec.Template.Spec.Containers = append(containers, container)

		return injectedDeployment
	}

	// GIVEN
	dummyDeployment1 := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-deploy-1",
		},
		Spec: appsv1.DeploymentSpec{
			Template: v1.PodTemplateSpec{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:  "nginx",
							Image: "nginx",
						},
					},
				},
			},
		},
	}
	dummyDeployment2 := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-deploy-2",
		},
		Spec: appsv1.DeploymentSpec{
			Template: v1.PodTemplateSpec{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:  "echo-server",
							Image: "ghcr.io/wzshiming/echoserver/echoserver:v0.0.1",
						},
					},
				},
			},
		},
	}

	sidecar := v1.Container{Name: "sidecar", Image: "fake-image"}
	expectedDeployment1 := appendContainer(dummyDeployment1, sidecar)
	expectedDeployment2 := appendContainer(dummyDeployment2, sidecar)

	injector := injectorImpl{
		objects: []*unstructured.Unstructured{
			toUnstructured(dummyDeployment1),
			toUnstructured(dummyDeployment2),
		},
	}

	expected := []*unstructured.Unstructured{
		toUnstructured(expectedDeployment1),
		toUnstructured(expectedDeployment2),
	}

	// WHEN
	actual, err := injector.Inject(Sidecar{Container: sidecar})

	// THEN
	if assert.NoError(t, err) {
		assert.Equal(t, expected, actual)
	}
}

func Test_InjectableDeploymentMeta(t *testing.T) {
	toUnstructured := func(obj runtime.Object) *unstructured.Unstructured {
		u, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&obj)
		if err != nil {
			panic(err)
		}
		return &unstructured.Unstructured{Object: u}
	}

	t.Run("returns metadata from the first injectable Deployment", func(t *testing.T) {
		deployment := &appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "web-frontend",
				Namespace: "production",
			},
			Spec: appsv1.DeploymentSpec{
				Template: v1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{"app": "web", "tier": "frontend"},
					},
					Spec: v1.PodSpec{
						Containers: []v1.Container{{Name: "nginx", Image: "nginx"}},
					},
				},
			},
		}

		inj := injectorImpl{objects: []*unstructured.Unstructured{toUnstructured(deployment)}}

		meta, err := inj.InjectableDeploymentMeta()
		if assert.NoError(t, err) {
			assert.Equal(t, "web-frontend", meta.Name)
			assert.Equal(t, "production", meta.Namespace)
			assert.Equal(t, map[string]string{"app": "web", "tier": "frontend"}, meta.Labels)
		}
	})

	t.Run("defaults namespace to 'default' when not set", func(t *testing.T) {
		deployment := &appsv1.Deployment{
			TypeMeta:   metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "worker"},
			Spec: appsv1.DeploymentSpec{
				Template: v1.PodTemplateSpec{
					Spec: v1.PodSpec{
						Containers: []v1.Container{{Name: "worker", Image: "python:3.12"}},
					},
				},
			},
		}

		inj := injectorImpl{objects: []*unstructured.Unstructured{toUnstructured(deployment)}}

		meta, err := inj.InjectableDeploymentMeta()
		if assert.NoError(t, err) {
			assert.Equal(t, "default", meta.Namespace)
		}
	})

	t.Run("returns error when no injectable Deployment exists", func(t *testing.T) {
		// A ConfigMap is not injectable
		configMap := &v1.ConfigMap{
			TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "my-config"},
		}

		inj := injectorImpl{objects: []*unstructured.Unstructured{toUnstructured(configMap)}}

		_, err := inj.InjectableDeploymentMeta()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no injectable Deployment found")
	})
}

func Test_InjectPodSettings(t *testing.T) {
	hostPath := func(name, path string) v1.Volume {
		return v1.Volume{Name: name, VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: path}}}
	}
	deploymentWith := func(volumes ...v1.Volume) *unstructured.Unstructured {
		var obj runtime.Object = &appsv1.Deployment{
			TypeMeta:   metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "web"},
			Spec: appsv1.DeploymentSpec{
				Template: v1.PodTemplateSpec{
					Spec: v1.PodSpec{
						Containers: []v1.Container{{Name: "nginx", Image: "nginx"}},
						Volumes:    volumes,
					},
				},
			},
		}
		u, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&obj)
		if err != nil {
			panic(err)
		}
		return &unstructured.Unstructured{Object: u}
	}
	podSpecOf := func(t *testing.T, obj *unstructured.Unstructured) v1.PodSpec {
		t.Helper()
		deployment, err := toDeployment(obj)
		if err != nil {
			t.Fatal(err)
		}
		return deployment.Spec.Template.Spec
	}
	sidecar := Sidecar{
		Container: v1.Container{Name: "sidecar", Image: "fake-image"},
		Volumes:   []v1.Volume{hostPath("host-proc", "/proc"), hostPath("sys-fs-bpf", "/sys/fs/bpf")},
		HostPID:   true,
	}

	t.Run("adds the volumes and hostPID", func(t *testing.T) {
		inj := injectorImpl{objects: []*unstructured.Unstructured{deploymentWith(hostPath("data", "/data"))}}
		out, err := inj.Inject(sidecar)
		if assert.NoError(t, err) {
			spec := podSpecOf(t, out[0])
			assert.True(t, spec.HostPID)
			assert.Equal(t, []v1.Volume{hostPath("data", "/data"), hostPath("host-proc", "/proc"), hostPath("sys-fs-bpf", "/sys/fs/bpf")}, spec.Volumes)
			assert.Equal(t, []string{"nginx", "sidecar"}, []string{spec.Containers[0].Name, spec.Containers[1].Name})
		}
	})

	t.Run("keeps a volume the pod has with the same name and path", func(t *testing.T) {
		inj := injectorImpl{objects: []*unstructured.Unstructured{deploymentWith(hostPath("host-proc", "/proc"))}}
		out, err := inj.Inject(sidecar)
		if assert.NoError(t, err) {
			assert.Equal(t, []v1.Volume{hostPath("host-proc", "/proc"), hostPath("sys-fs-bpf", "/sys/fs/bpf")}, podSpecOf(t, out[0]).Volumes)
		}
	})

	t.Run("refuses a volume the pod has with the same name and another source", func(t *testing.T) {
		emptyDir := v1.Volume{Name: "host-proc", VolumeSource: v1.VolumeSource{EmptyDir: &v1.EmptyDirVolumeSource{}}}
		for _, existing := range []v1.Volume{hostPath("host-proc", "/var/proc"), emptyDir} {
			inj := injectorImpl{objects: []*unstructured.Unstructured{deploymentWith(existing)}}
			_, err := inj.Inject(sidecar)
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), `Deployment web`)
				assert.Contains(t, err.Error(), `"host-proc"`)
			}
		}
	})

	t.Run("refuses a pod that shares its process namespace", func(t *testing.T) {
		obj := deploymentWith()
		if err := unstructured.SetNestedField(obj.Object, true, "spec", "template", "spec", "shareProcessNamespace"); err != nil {
			t.Fatal(err)
		}
		inj := injectorImpl{objects: []*unstructured.Unstructured{obj}}
		_, err := inj.Inject(sidecar)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Deployment web")
			assert.Contains(t, err.Error(), "shareProcessNamespace")
		}
		// Without hostPID the sidecar fits such a pod.
		_, err = inj.Inject(Sidecar{Container: sidecar.Container})
		assert.NoError(t, err)
	})

	t.Run("changes no pod settings without volumes or hostPID", func(t *testing.T) {
		inj := injectorImpl{objects: []*unstructured.Unstructured{deploymentWith()}}
		out, err := inj.Inject(Sidecar{Container: sidecar.Container})
		if assert.NoError(t, err) {
			spec := podSpecOf(t, out[0])
			assert.False(t, spec.HostPID)
			assert.Empty(t, spec.Volumes)
		}
	})
}
