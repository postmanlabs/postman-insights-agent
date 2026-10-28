package apidump

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/stretchr/testify/assert"
)

func TestCreateApplication_ConcurrentPodsOnSameWorkspace_ShareOneRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := rest.NewMockFrontClient(ctrl)
	a := &apidump{Args: &Args{WorkspaceID: "ws-concurrent", SystemEnv: "env-1"}}
	t.Cleanup(func() { rest.IngestCooldown.Clear(rest.WorkspaceCooldownKey("ws-concurrent", "env-1")) })

	called := make(chan struct{})
	release := make(chan struct{})
	client.EXPECT().
		CreateApplication(gomock.Any(), "ws-concurrent", "env-1").
		DoAndReturn(func(context.Context, string, string) (rest.CreateApplicationResponse, error) {
			close(called)
			<-release
			return rest.CreateApplicationResponse{}, rest.IngestDisabledError{RetryAfter: time.Minute, Message: "not linked"}
		}).
		Times(1)

	const pods = 10
	errs := make([]error, pods)
	var wg sync.WaitGroup
	for i := range pods {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = a.createApplication(client)
		}()
	}
	<-called
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()

	for _, err := range errs {
		assert.True(t, rest.IsIngestDisabledError(err))
	}
}

func TestCreateApplication_CooldownActive_SkipsRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	client := rest.NewMockFrontClient(ctrl)
	a := &apidump{Args: &Args{WorkspaceID: "ws-cooldown", SystemEnv: "env-1"}}
	key := rest.WorkspaceCooldownKey("ws-cooldown", "env-1")
	rest.IngestCooldown.Mark(key, time.Hour)
	t.Cleanup(func() { rest.IngestCooldown.Clear(key) })

	_, err := a.createApplication(client)

	ingestErr, ok := rest.AsIngestDisabledError(err)
	assert.True(t, ok)
	assert.Greater(t, ingestErr.RetryAfter, 59*time.Minute)
}
