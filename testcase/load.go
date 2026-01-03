package testcase

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadFile reads and validates a testcase YAML file.
func LoadFile(path string) (Case, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Case{}, err
	}
	return LoadBytes(data)
}

// LoadBytes parses and validates a testcase YAML payload.
func LoadBytes(data []byte) (Case, error) {
	var c Case
	if err := yaml.Unmarshal(data, &c); err != nil {
		return Case{}, fmt.Errorf("testcase: invalid yaml: %w", err)
	}
	if err := c.Validate(); err != nil {
		return Case{}, err
	}
	return c, nil
}
