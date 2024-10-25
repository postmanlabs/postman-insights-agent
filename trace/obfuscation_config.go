package trace

import (
	"embed"
	"strings"
	"sync"

	"github.com/akitasoftware/go-utils/sets"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

var (
	//go:embed obfuscation_config.yaml
	obfucationFileFS embed.FS

	onceConfigLoad sync.Once
	config         obfuscationConfig
	configErr      error = nil
)

type obfuscationConfig struct {
	SensitiveKeys         []string `yaml:"sensitive_keys"`
	SensitiveValueRegexes []string `yaml:"sensitive_value_regexes"`
}

func (c *obfuscationConfig) sanitizeConfigData() bool {

	// Convert all the keys to lower case and remove duplicates
	keys := sets.NewSet[string]()
	for _, key := range c.SensitiveKeys {
		keys.Insert(strings.ToLower(key))
	}
	c.SensitiveKeys = keys.AsSlice()

	return false
}

func loadConfigFromFile() (*obfuscationConfig, error) {
	onceConfigLoad.Do(func() {
		data, err := obfucationFileFS.Open("obfuscation_config.yaml")
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
