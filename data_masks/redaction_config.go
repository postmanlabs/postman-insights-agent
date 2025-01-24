package data_masks

import (
	"embed"
	"strings"
	"sync"

	"github.com/akitasoftware/go-utils/sets"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

var (
	//go:embed redaction_config.yaml
	redactionFileFS embed.FS

	onceConfigLoad sync.Once
	config         redactionConfig
	configErr      error = nil
)

type redactionConfig struct {
	SensitiveKeys         []string `yaml:"sensitive_keys"`
	SensitiveValueRegexes []string `yaml:"sensitive_value_regexes"`
}

func (c *redactionConfig) sanitizeConfigData() bool {

	// Convert all the keys to lower case and remove duplicates
	keys := sets.NewSet[string]()
	for _, key := range c.SensitiveKeys {
		keys.Insert(strings.ToLower(key))
	}
	c.SensitiveKeys = keys.AsSlice()

	return false
}

func loadConfigFromFile() (*redactionConfig, error) {
	onceConfigLoad.Do(func() {
		data, err := redactionFileFS.Open("redaction_config.yaml")
		if err != nil {
			configErr = errors.Wrap(err, "failed to open config file")
		}

		dec := yaml.NewDecoder(data)
		if err := dec.Decode(&config); err != nil {
			configErr = errors.Wrap(err, "failed to parse YAML")
		}

		config.sanitizeConfigData()
	})

	return &config, configErr
}
