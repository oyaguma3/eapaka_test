package config

import (
	"fmt"
	"strings"

	"github.com/oyaguma3/eapaka_test/conformance"
)

// Config represents the tool configuration loaded from YAML.
type Config struct {
	Radius      RadiusConfig      `yaml:"radius"`
	RadiusAttrs RadiusAttrs       `yaml:"radius_attrs"`
	EAP         EAPConfig         `yaml:"eap"`
	Identity    IdentityConfig    `yaml:"identity"`
	SIM         SIMConfig         `yaml:"sim"`
	SQNStore    SQNStoreConfig    `yaml:"sqn_store"`
	Conformance ConformanceConfig `yaml:"conformance"`
	MPPE        MPPEConfig        `yaml:"mppe"`
}

// MPPEConfig は MS-MPPE 鍵と MSK の対応付け（設計書 §6.2）。
// Mapping が "rfc5216" なら Recv-Key = MSK[0:32]、Send-Key = MSK[32:64]（RFC 5216 §2.3 と
// hostapd の慣行）。"swapped" なら逆にする。
type MPPEConfig struct {
	Mapping string `yaml:"mapping"`
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

// NakConfig は強制 Nak（X5）。On のタイプを提示されたら Propose を希望する Nak を返す。
type NakConfig struct {
	On      []uint8 `yaml:"on"`
	Propose []uint8 `yaml:"propose"`
}

type EAPConfig struct {
	// MethodPreference は使ってよい EAP メソッドの希望順（X5）。空なら [50, 23]。
	MethodPreference []uint8   `yaml:"method_preference"`
	Nak              NakConfig `yaml:"nak"`
	// BiddingPolicy は EAP-AKA の AT_BIDDING（D=1）の扱い（reject / ignore、RFC 9048 §4）。
	BiddingPolicy string `yaml:"bidding_policy"`

	MethodMismatchPolicy              string         `yaml:"method_mismatch_policy"`
	OuterIdentityUpdateOnPermanentReq *bool          `yaml:"outer_identity_update_on_permanent_req"`
	PermanentIDPolicy                 string         `yaml:"permanent_id_policy"`
	AKAPrime                          AKAPrimeConfig `yaml:"aka_prime"`
}

type AKAPrimeConfig struct {
	NetName string `yaml:"net_name"`
	// NetNameCheck は AT_KDF_INPUT と net_name の照合（off / warn / reject、設計書 §6.3）。
	NetNameCheck string `yaml:"net_name_check"`
	// EmptyKdfInput は空の AT_KDF_INPUT の扱い（reject / fallback、設計書 §6.3）。
	EmptyKdfInput string `yaml:"empty_kdf_input"`
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

// ConformanceConfig はサーバ準拠性チェッカのポリシー（設計書 §6.1、§7.1）。
// 値は fail / warn / off。Rules は規則 ID ごとの上書き。
type ConformanceConfig struct {
	DefaultMust   string            `yaml:"default_must"`
	DefaultShould string            `yaml:"default_should"`
	Rules         map[string]string `yaml:"rules"`
}

// Policy は設定を conformance.Policy に変換する。
func (c ConformanceConfig) Policy() (conformance.Policy, error) {
	p := conformance.DefaultPolicy()
	var err error
	if c.DefaultMust != "" {
		if p.DefaultMust, err = conformance.ParseAction(c.DefaultMust); err != nil {
			return p, fmt.Errorf("config: conformance.default_must: %w", err)
		}
	}
	if c.DefaultShould != "" {
		if p.DefaultShould, err = conformance.ParseAction(c.DefaultShould); err != nil {
			return p, fmt.Errorf("config: conformance.default_should: %w", err)
		}
	}
	rules, err := ParseConformanceRules(c.Rules)
	if err != nil {
		return p, fmt.Errorf("config: conformance.rules: %w", err)
	}
	p.Rules = rules
	return p, nil
}

// ParseConformanceRules は規則 ID ごとの設定値を検証して変換する。
func ParseConformanceRules(rules map[string]string) (map[string]conformance.Action, error) {
	out := make(map[string]conformance.Action, len(rules))
	for id, v := range rules {
		if _, ok := conformance.Lookup(id); !ok {
			return nil, fmt.Errorf("unknown rule %q", id)
		}
		a, err := conformance.ParseAction(v)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", id, err)
		}
		out[id] = a
	}
	return out, nil
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
	if c.EAP.AKAPrime.NetNameCheck == "" {
		c.EAP.AKAPrime.NetNameCheck = "off"
	}
	if c.EAP.AKAPrime.EmptyKdfInput == "" {
		c.EAP.AKAPrime.EmptyKdfInput = "reject"
	}
	if c.EAP.BiddingPolicy == "" {
		c.EAP.BiddingPolicy = "reject"
	}
	if c.MPPE.Mapping == "" {
		c.MPPE.Mapping = "rfc5216"
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
	if !isOneOf(c.EAP.AKAPrime.NetNameCheck, "off", "warn", "reject") {
		return fmt.Errorf("config: eap.aka_prime.net_name_check must be off, warn, or reject")
	}
	if !isOneOf(c.EAP.AKAPrime.EmptyKdfInput, "reject", "fallback") {
		return fmt.Errorf("config: eap.aka_prime.empty_kdf_input must be reject or fallback")
	}
	if !isOneOf(c.EAP.BiddingPolicy, "reject", "ignore") {
		return fmt.Errorf("config: eap.bidding_policy must be reject or ignore")
	}
	if err := validateMethods("config: eap.method_preference", c.EAP.MethodPreference); err != nil {
		return err
	}
	if err := validateMethods("config: eap.nak.on", c.EAP.Nak.On); err != nil {
		return err
	}
	if !isOneOf(c.MPPE.Mapping, "rfc5216", "swapped") {
		return fmt.Errorf("config: mppe.mapping must be rfc5216 or swapped")
	}
	if _, err := c.Conformance.Policy(); err != nil {
		return err
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

// validateMethods は、EAP-AKA（23）と EAP-AKA'（50）だけが指定されていることを確かめる。
func validateMethods(label string, methods []uint8) error {
	for _, m := range methods {
		if m != 23 && m != 50 {
			return fmt.Errorf("%s: unsupported EAP type %d (use 23 or 50)", label, m)
		}
	}
	return nil
}
