package legacy

import (
	"context"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/pkg/errors"
	"github.com/postmanlabs/postman-insights-agent/rest"
)

func getServiceIDByName(c rest.FrontClient, name string) (akid.ServiceID, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	services, err := c.GetServices(ctx)
	if err != nil {
		return akid.ServiceID{}, errors.Wrap(err, "failed to get list of services associated with the account")
	}

	var serviceID akid.ServiceID
	for _, svc := range services {
		if svc.Name == name {
			serviceID = svc.ID
			break
		}
	}
	if serviceID == (akid.ServiceID{}) {
		return akid.ServiceID{}, errors.Errorf("cannot determine service ID for %s", name)
	}
	return serviceID, nil
}
