package rest

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/api_schema"
	kgxapi "github.com/akitasoftware/akita-libs/api_schema"
	"github.com/akitasoftware/akita-libs/path_trie"
	"github.com/akitasoftware/akita-libs/tags"
)

var (
	// Value that will be marshalled into an empty JSON object.
	emptyObject = map[string]interface{}{}
)

type learnClientImpl struct {
	BaseClient

	serviceID akid.ServiceID
}

var _ LearnClient = (*learnClientImpl)(nil)

func NewLearnClient(host string, cli akid.ClientID, svc akid.ServiceID) *learnClientImpl {
	return &learnClientImpl{
		BaseClient: NewBaseClient(host, cli),
		serviceID:  svc,
	}
}

func (c *learnClientImpl) ListLearnSessions(ctx context.Context, svc akid.ServiceID, tags map[tags.Key]string, limit int, offset int) ([]*kgxapi.ListedLearnSession, error) {
	p := path.Join("/v2/agent/services", akid.String(c.serviceID), "learn")
	q := url.Values{}
	q.Add("limit", strconv.Itoa(limit))
	q.Add("offset", strconv.Itoa(offset))
	for k, v := range tags {
		q.Add(fmt.Sprintf("tag[%s]", k), v)
	}

	var resp kgxapi.ListSessionsResponse
	err := c.GetWithQuery(ctx, p, q, &resp)
	if err != nil {
		return nil, err
	}
	return resp.Sessions, nil
}

func (c *learnClientImpl) ListLearnSessionsWithStats(ctx context.Context, svc akid.ServiceID, limit int) ([]*kgxapi.ListedLearnSession, error) {
	p := path.Join("/v2/agent/services", akid.String(c.serviceID), "learn")
	q := url.Values{}
	q.Add("limit", fmt.Sprintf("%d", limit))
	q.Add("get_stats", "true")

	var resp kgxapi.ListSessionsResponse
	err := c.GetWithQuery(ctx, p, q, &resp)
	if err != nil {
		return nil, err
	}
	return resp.Sessions, nil
}

// Deprecated: Only used in learn command which is deprecated.
func (c *learnClientImpl) GetLearnSession(ctx context.Context, svc akid.ServiceID, lrn akid.LearnSessionID) (*kgxapi.LearnSession, error) {
	p := path.Join("/v1/services", akid.String(c.serviceID), "learn", akid.String(lrn))
	var resp kgxapi.LearnSession
	err := c.Get(ctx, p, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *learnClientImpl) CreateLearnSession(ctx context.Context, baseSpecRef *kgxapi.APISpecReference, name string, tags map[tags.Key]string) (akid.LearnSessionID, error) {
	req := kgxapi.CreateLearnSessionRequest{BaseAPISpecRef: baseSpecRef, Tags: tags, Name: name}
	var resp kgxapi.LearnSession
	p := path.Join("/v2/agent/services", akid.String(c.serviceID), "learn")
	err := c.Post(ctx, p, req, &resp)
	if err != nil {
		return akid.LearnSessionID{}, err
	}
	return resp.ID, nil
}

func (c *learnClientImpl) GetDynamicAgentConfigForService(
	ctx context.Context,
	serviceID akid.ServiceID,
) (*kgxapi.ServiceAgentConfig, error) {
	var resp kgxapi.ServiceAgentConfig
	p := path.Join("/v2/agent/services", c.serviceID.String(), "settings")
	err := c.Get(ctx, p, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *learnClientImpl) AsyncReportsUpload(ctx context.Context, lrn akid.LearnSessionID, req *kgxapi.UploadReportsRequest) error {
	req.ClientID = c.clientID
	resp := map[string]interface{}{}

	p := path.Join("/v2/agent/services", akid.String(c.serviceID), "learn", akid.String(lrn), "async_reports")
	return c.Post(ctx, p, req, &resp)
}

// Deprecated: Function not used anywhere.
func (c *learnClientImpl) CreateSpec(ctx context.Context, name string, lrns []akid.LearnSessionID, opts CreateSpecOptions) (akid.APISpecID, error) {
	// Go cannot marshal regexp into JSON unfortunately.
	pathExclusions := make([]string, len(opts.PathExclusions))
	for i, e := range opts.PathExclusions {
		pathExclusions[i] = e.String()
	}

	req := map[string]interface{}{
		"name":              name,
		"learn_session_ids": lrns,
		"path_exclusions":   pathExclusions,
		"tags":              opts.Tags,
		"versions":          opts.Versions,
	}
	if opts.GitHubPR != nil {
		req["github_pr"] = opts.GitHubPR
	}
	if opts.GitLabMR != nil {
		req["gitlab_mr"] = opts.GitLabMR
	}
	if opts.TimeRange != nil {
		req["time_range"] = opts.TimeRange
	}

	p := path.Join("/v1/services", akid.String(c.serviceID), "specs")
	var resp kgxapi.CreateSpecResponse
	err := c.Post(ctx, p, req, &resp)
	return resp.ID, err
}

// Used only for integration tests
func (c *learnClientImpl) GetSpec(ctx context.Context, api akid.APISpecID, opts GetSpecOptions) (kgxapi.GetSpecResponse, error) {
	qs := make(url.Values)
	if !opts.EnableRelatedTypes {
		qs.Add("strip_related_annotations", "true")
	}
	p := path.Join("/v2/agent/services", akid.String(c.serviceID), "specs", akid.String(api))

	var resp kgxapi.GetSpecResponse
	err := c.GetWithQuery(ctx, p, qs, &resp)
	return resp, err
}

// Deprecated: Used only in get command which is deprecated.
func (c *learnClientImpl) ListSpecs(ctx context.Context) ([]kgxapi.SpecInfo, error) {
	qs := make(url.Values)

	// Set limit to 0 to ensure no pagination is applied.
	qs.Add("limit", "0")
	qs.Add("offset", "0")

	p := path.Join("/v1/services", akid.String(c.serviceID), "specs")

	var resp kgxapi.ListSpecsResponse
	err := c.GetWithQuery(ctx, p, qs, &resp)
	return resp.Specs, err
}

// Used only for integration tests
func (c *learnClientImpl) GetSpecVersion(ctx context.Context, version string) (kgxapi.APISpecVersion, error) {
	var resp kgxapi.APISpecVersion
	p := path.Join("/v2/agent/services", akid.String(c.serviceID), "spec-versions", version)
	err := c.Get(ctx, p, &resp)
	if err != nil {
		return kgxapi.APISpecVersion{}, err
	}
	return resp, nil
}

// Deprecated: Used in upload command which is deprecated.
func (c *learnClientImpl) UploadSpec(ctx context.Context, req kgxapi.UploadSpecRequest) (*kgxapi.UploadSpecResponse, error) {
	p := path.Join("/v1/services", akid.String(c.serviceID), "upload-spec")
	var resp kgxapi.UploadSpecResponse
	err := c.Post(ctx, p, req, &resp)
	return &resp, err
}

// Deprecated: Used in apidiff, get and set command which are deprecated.
func (c *learnClientImpl) GetAPISpecIDByName(ctx context.Context, n string) (akid.APISpecID, error) {
	resp := struct {
		ID akid.APISpecID `json:"id"`
	}{}
	path := fmt.Sprintf("/v1/services/%s/ids/specs/%s", akid.String(c.serviceID), n)
	err := c.Get(ctx, path, &resp)
	return resp.ID, err
}

func (c *learnClientImpl) GetLearnSessionIDByName(ctx context.Context, n string) (akid.LearnSessionID, error) {
	resp := struct {
		ID akid.LearnSessionID `json:"id"`
	}{}
	path := fmt.Sprintf("/v1/services/%s/ids/learn_sessions/%s", akid.String(c.serviceID), n)
	err := c.Get(ctx, path, &resp)
	return resp.ID, err
}

// Deprecated: Used in apidiff command which is deprecated.
func (c *learnClientImpl) GetSpecDiffTrie(ctx context.Context, baseID, newID akid.APISpecID) (*path_trie.PathTrie, error) {
	var resp path_trie.PathTrie
	path := fmt.Sprintf("/v1/services/%s/specs/%s/diff/%s/trie",
		akid.String(c.serviceID), akid.String(baseID), akid.String(newID))
	err := c.Get(ctx, path, &resp)
	return &resp, err
}

func (c *learnClientImpl) PostClientPacketCaptureStats(ctx context.Context, serviceID akid.ServiceID, req kgxapi.PostClientPacketCaptureStatsRequest) error {
	path := fmt.Sprintf("/v2/agent/services/%s/telemetry/client/deployment", serviceID)
	var resp struct{}
	return c.Post(ctx, path, req, &resp)
}

func (c *learnClientImpl) PostInitialClientTelemetry(ctx context.Context, serviceID akid.ServiceID, req kgxapi.PostInitialClientTelemetryRequest) error {
	path := fmt.Sprintf("/v2/agent/services/%s/telemetry/client/deployment/start", serviceID)
	var resp struct{}
	return c.Post(ctx, path, req, &resp)
}

// Deprecated: Used in setversion command which is deprecated.
func (c *learnClientImpl) SetSpecVersion(ctx context.Context, specID akid.APISpecID, versionName string) error {
	resp := struct {
	}{}
	path := fmt.Sprintf("/v1/services/%s/spec-versions/%s",
		akid.String(c.serviceID), versionName)
	req := kgxapi.SetSpecVersionRequest{
		APISpecID: specID,
	}

	return c.Post(ctx, path, req, &resp)
}

// Returns events aggregated in 1-minute intervals.
// Deprecated: Used in get command which is deprecated.
func (c *learnClientImpl) GetTimeline(ctx context.Context, serviceID akid.ServiceID, deployment string, start time.Time, end time.Time, limit int) (kgxapi.TimelineResponse, error) {
	path := fmt.Sprintf("/v1/services/%s/timeline/%s/query",
		akid.String(serviceID), deployment)
	q := url.Values{}
	q.Add("start", fmt.Sprintf("%d", start.Unix()*1000000))
	q.Add("end", fmt.Sprintf("%d", end.Unix()*1000000))
	q.Add("limit", fmt.Sprintf("%d", limit))
	q.Add("bucket", "1m")
	// Separate out by response code
	q.Add("key", "host")
	q.Add("key", "method")
	q.Add("key", "path")
	q.Add("key", "code")
	q.Add("aggregate", string(api_schema.Aggr_99p))

	var resp kgxapi.TimelineResponse
	err := c.GetWithQuery(ctx, path, q, &resp)
	return resp, err
}

// Return the edges of the service graph in the specified time window
// Deprecated: Used in get command which is deprecated.
func (c *learnClientImpl) GetGraphEdges(ctx context.Context, serviceID akid.ServiceID, deployment string, start time.Time, end time.Time, graphType string) (kgxapi.GraphResponse, error) {
	path := fmt.Sprintf("/v1/services/%s/servicegraph/%s/query",
		akid.String(serviceID), deployment)
	q := url.Values{}
	q.Add("start", fmt.Sprintf("%d", start.Unix()*1000000))
	q.Add("end", fmt.Sprintf("%d", end.Unix()*1000000))
	q.Add("type", graphType)

	var resp kgxapi.GraphResponse
	err := c.GetWithQuery(ctx, path, q, &resp)
	return resp, err
}
