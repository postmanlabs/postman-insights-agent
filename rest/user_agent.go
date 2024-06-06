package rest

import (
	"runtime"

	"github.com/postmanlabs/postman-insights-agent/env"
	"github.com/postmanlabs/postman-insights-agent/useragent"
	"github.com/postmanlabs/postman-insights-agent/version"
)

func GetUserAgent() string {
	e := useragent.ENV_HOST
	if env.InDocker() {
		e = useragent.ENV_DOCKER
	}

	ua := useragent.UA{
		Version: version.ReleaseVersion(),
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
		EnvType: e,
	}
	return ua.String()
}
