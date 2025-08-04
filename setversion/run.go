package setversion

import (
	"context"
	"time"

	"github.com/postmanlabs/postman-insights-agent/rest"
	"github.com/postmanlabs/postman-insights-agent/util"
)

func Run(args Args) error {
	// Resolve service ID.
	frontClient := rest.NewFrontClient(args.Domain, args.ClientID, nil, nil)
	serviceName := args.ModelURI.ServiceName
	serviceID, err := util.GetServiceIDByName(frontClient, serviceName)
	if err != nil {
		return err
	}

	// Resolve API model ID.
	learnClient := rest.NewLearnClient(args.Domain, args.ClientID, serviceID, nil, nil)
	modelID, err := util.ResolveSpecURI(learnClient, args.ModelURI)
	if err != nil {
		return err
	}

	// Set version name.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return learnClient.SetSpecVersion(ctx, modelID, args.VersionName)
}
