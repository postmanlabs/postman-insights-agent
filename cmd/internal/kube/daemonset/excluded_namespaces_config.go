package daemonset

import (
	"embed"
	"sync"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

var (
	//go:embed excluded_namespaces.yaml
	excludedNamespacesFS embed.FS

	onceExcludedNSLoad sync.Once
	excludedNSConfig   excludedNamespacesConfig
	excludedNSErr      error
)

type excludedNamespacesConfig struct {
	ExcludedNamespaces []string `yaml:"excluded_namespaces"`
}

func loadExcludedNamespacesFromFile() ([]string, error) {
	onceExcludedNSLoad.Do(func() {
		data, err := excludedNamespacesFS.ReadFile("excluded_namespaces.yaml")
		if err != nil {
			excludedNSErr = errors.Wrap(err, "failed to read excluded namespaces config")
			return
		}

		if err := yaml.Unmarshal(data, &excludedNSConfig); err != nil {
			excludedNSErr = errors.Wrap(err, "failed to parse excluded namespaces YAML")
		}
	})

	return excludedNSConfig.ExcludedNamespaces, excludedNSErr
}
