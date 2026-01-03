package config

import (
	"fmt"
	"strings"
)

// Config represents the tool configuration loaded from YAML.
type Config struct {
	Radius      RadiusConfig   `yaml:"radius"`
	RadiusAttrs RadiusAttrs    `yaml:"radius_attrs"`
	EAP         EAPConfig      `yaml:"eap"`
	Identity    IdentityConfig `yaml:"identity"`
	SIM         SIMConfig      `yaml:"sim"`
	SQNStore    SQNStoreConfig `yaml:"sqn_store"`
}

type RadiusConfig struct {
	ServerAddr string `yaml:"server_addr"`
	Secret     string `yaml:"secret"`
	TimeoutMS  int    `yaml:"timeout_ms"`
	Retries    int    `yaml:"retries"`
}

type RadiusAttrs struct {
	NASIPAddress     string `yaml:"nas_ip_address"`
	NASIdentifier    string `yaml:"nas_identifier"`
	CalledStationID  string `yaml:"called_station_id"`
	CallingStationID string `yaml:"calling_station_id"`
}

type EAPConfig struct {
	MethodMismatchPolicy              string         `yaml:"method_mismatch_policy"`
	OuterIdentityUpdateOnPermanentReq *bool          `yaml:"outer_identity_update_on_permanent_req"`
	PermanentIDPolicy                 string         `yaml:"permanent_id_policy"`
	AKAPrime                          AKAPrimeConfig `yaml:"aka_prime"`
}

type AKAPrimeConfig struct {
	NetName string `yaml:"net_name"`
}

type IdentityConfig struct {
	Realm string `yaml:"realm"`
}

type SIMConfig struct {
	IMSI          string `yaml:"imsi"`
	KI            string `yaml:"ki"`
	OPC           string `yaml:"opc"`
	AMF           string `yaml:"amf"`
	SQNInitialHex string `yaml:"sqn_initial_hex"`
}

type SQNStoreConfig struct {
	Mode string `yaml:"mode"`
	Path string `yaml:"path"`
}

const (
	DefaultTimeoutMS            = 1000
	DefaultRetries              = 3
	DefaultMethodMismatchPolicy = "warn"
	DefaultPermanentIDPolicy    = "always"
)

// ApplyDefaults sets defaults for optional config fields.
func (c *Config) ApplyDefaults() {
	if c.Radius.TimeoutMS == 0 {
		c.Radius.TimeoutMS = DefaultTimeoutMS
	}
	if c.Radius.Retries == 0 {
		c.Radius.Retries = DefaultRetries
	}
	if c.EAP.MethodMismatchPolicy == "" {
		c.EAP.MethodMismatchPolicy = DefaultMethodMismatchPolicy
	}
	if c.EAP.PermanentIDPolicy == "" {
		c.EAP.PermanentIDPolicy = DefaultPermanentIDPolicy
	}
	if c.EAP.OuterIdentityUpdateOnPermanentReq == nil {
		value := true
		c.EAP.OuterIdentityUpdateOnPermanentReq = &value
	}
	if c.SQNStore.Mode == "" {
		c.SQNStore.Mode = "file"
	}
}

// Validate checks required fields and basic format constraints.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Radius.ServerAddr) == "" {
		return fmt.Errorf("config: radius.server_addr is required")
	}
	if strings.TrimSpace(c.Radius.Secret) == "" {
		return fmt.Errorf("config: radius.secret is required")
	}
	if strings.TrimSpace(c.SIM.IMSI) == "" {
		return fmt.Errorf("config: sim.imsi is required")
	}
	if err := validateHexLen("config: sim.ki", c.SIM.KI, 32); err != nil {
		return err
	}
	if err := validateHexLen("config: sim.opc", c.SIM.OPC, 32); err != nil {
		return err
	}
	if err := validateHexLen("config: sim.amf", c.SIM.AMF, 4); err != nil {
		return err
	}
	if err := validateHexLen("config: sim.sqn_initial_hex", c.SIM.SQNInitialHex, 12); err != nil {
		return err
	}
	switch c.SQNStore.Mode {
	case "memory", "file":
	default:
		return fmt.Errorf("config: sqn_store.mode must be memory or file")
	}
	if c.SQNStore.Mode == "file" && strings.TrimSpace(c.SQNStore.Path) == "" {
		return fmt.Errorf("config: sqn_store.path is required for file mode")
	}
	if !isOneOf(c.EAP.MethodMismatchPolicy, "strict", "warn", "allow") {
		return fmt.Errorf("config: eap.method_mismatch_policy must be strict, warn, or allow")
	}
	if !isOneOf(c.EAP.PermanentIDPolicy, "always", "conservative", "deny") {
		return fmt.Errorf("config: eap.permanent_id_policy must be always, conservative, or deny")
	}
	return nil
}

func validateHexLen(label, value string, expected int) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s is required", label)
	}
	if len(value) != expected {
		return fmt.Errorf("%s must be %d hex chars", label, expected)
	}
	if len(value)%2 != 0 {
		return fmt.Errorf("%s must be even-length hex", label)
	}
	for _, r := range value {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			continue
		}
		return fmt.Errorf("%s must be hex", label)
	}
	return nil
}

func isOneOf(value string, allowed ...string) bool {
	for _, v := range allowed {
		if value == v {
			return true
		}
	}
	return false
}
