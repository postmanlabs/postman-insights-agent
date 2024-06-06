package upload

import (
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/akiuri"
	"github.com/akitasoftware/akita-libs/tags"
	"github.com/postmanlabs/postman-insights-agent/plugin"
)

type Args struct {
	// Required args
	ClientID akid.ClientID
	Domain   string

	DestURI   akiuri.URI
	FilePaths []string

	// Optional args
	Tags            map[tags.Key]string
	Append          bool
	IncludeTrackers bool
	UploadTimeout   time.Duration
	Plugins         []plugin.AkitaPlugin
}
