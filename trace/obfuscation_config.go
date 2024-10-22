package trace

import (
	"os"
	"strings"

	"github.com/akitasoftware/go-utils/sets"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
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

func configFromFile(n string) (*obfuscationConfig, error) {
	f, err := os.Open(n)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open config file")
	}
	defer f.Close()

	var c obfuscationConfig
	dec := yaml.NewDecoder(f)
	if err := dec.Decode(&c); err != nil {
		return nil, errors.Wrap(err, "failed to parse YAML")
	}

	c.sanitizeConfigData()

	return &c, nil
}
