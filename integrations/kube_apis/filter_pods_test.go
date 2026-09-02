package kube_apis

import (
	"testing"

	"github.com/stretchr/testify/assert"
	coreV1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const testAgentImage = "public.ecr.aws/postman/postman-insights-agent:latest"

func podWith(name string, images ...string) coreV1.Pod {
	containers := make([]coreV1.Container, 0, len(images))
	for i, img := range images {
		containers = append(containers, coreV1.Container{Name: string(rune('a' + i)), Image: img})
	}
	return coreV1.Pod{
		ObjectMeta: metaV1.ObjectMeta{Name: name},
		Spec:       coreV1.PodSpec{Containers: containers},
	}
}

func names(pods []coreV1.Pod) []string {
	out := make([]string, 0, len(pods))
	for _, p := range pods {
		out = append(out, p.Name)
	}
	return out
}

// The match is per pod, not per container. An app-plus-sidecar pod runs the
// agent and must be excluded by negate, even though its app container does not
// match -- that is the case the daemonset relies on to avoid capturing traffic
// the sidecar is already capturing.
func TestFilterPodsByContainerImage(t *testing.T) {
	appOnly := podWith("app-only", "example.com/app:1.0")
	appWithSidecar := podWith("app-with-sidecar", "example.com/app:1.0", testAgentImage)
	agentOnly := podWith("agent-only", testAgentImage)
	multiApp := podWith("multi-app", "example.com/app:1.0", "example.com/cache:2.0")

	pods := []coreV1.Pod{appOnly, appWithSidecar, agentOnly, multiApp}
	kc := &KubeClient{}

	without, err := kc.FilterPodsByContainerImage(pods, testAgentImage, true)
	assert.NoError(t, err)
	assert.Equal(t, []string{"app-only", "multi-app"}, names(without),
		"negate=true must return only pods that do not run the image anywhere")

	with, err := kc.FilterPodsByContainerImage(pods, testAgentImage, false)
	assert.NoError(t, err)
	assert.Equal(t, []string{"app-with-sidecar", "agent-only"}, names(with),
		"negate=false must return every pod that runs the image")
}

func TestFilterPodsByContainerImageHandlesNoContainers(t *testing.T) {
	kc := &KubeClient{}
	empty := coreV1.Pod{ObjectMeta: metaV1.ObjectMeta{Name: "no-containers"}}

	without, err := kc.FilterPodsByContainerImage([]coreV1.Pod{empty}, testAgentImage, true)
	assert.NoError(t, err)
	assert.Equal(t, []string{"no-containers"}, names(without))

	with, err := kc.FilterPodsByContainerImage([]coreV1.Pod{empty}, testAgentImage, false)
	assert.NoError(t, err)
	assert.Empty(t, with)
}
