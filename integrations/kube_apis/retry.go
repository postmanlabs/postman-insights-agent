package kube_apis

import (
	"time"

	"github.com/postmanlabs/postman-insights-agent/printer"
	kubeErrs "k8s.io/apimachinery/pkg/api/errors"
)

func isRetriableKubeErr(err error) bool {
	return kubeErrs.IsTimeout(err) ||
		kubeErrs.IsTooManyRequests(err) ||
		kubeErrs.IsServerTimeout(err) ||
		kubeErrs.IsServiceUnavailable(err) ||
		kubeErrs.IsInternalError(err) ||
		kubeErrs.IsUnexpectedServerError(err)
}

// backoffOnKubeAPIErr maps a Kubernetes API error to wait.ExponentialBackoff
// condition return values. Retriable errors return (false, nil) so the backoff
// loop continues; fatal errors return (false, err).
func backoffOnKubeAPIErr(err error, operation string) (bool, error) {
	if err == nil {
		return false, nil
	}
	if !isRetriableKubeErr(err) {
		return false, err
	}

	if sec, ok := kubeErrs.SuggestsClientDelay(err); ok && sec > 0 {
		printer.Warningf("%s: server requested retry after %ds: %v\n", operation, sec, err)
		time.Sleep(time.Duration(sec) * time.Second)
	} else {
		printer.Warningf("%s: retriable kube API error, retrying: %v\n", operation, err)
	}
	return false, nil
}
