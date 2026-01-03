package testcase

import (
	"fmt"
	"strings"
)

// Case represents a single test case session definition.
type Case struct {
	Version     int    `yaml:"version"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`

	Identity string `yaml:"identity"`

	Radius Radius `yaml:"radius"`
	EAP    EAP    `yaml:"eap"`
	SQN    SQN    `yaml:"sqn"`
	Expect Expect `yaml:"expect"`
	Trace  Trace  `yaml:"trace"`
}

type Radius struct {
	TimeoutMS *int        `yaml:"timeout_ms"`
	Retries   *int        `yaml:"retries"`
	Attrs     RadiusAttrs `yaml:"attributes"`
}

type RadiusAttrs struct {
	NASIPAddress     string `yaml:"nas_ip_address"`
	NASIdentifier    string `yaml:"nas_identifier"`
	CalledStationID  string `yaml:"called_station_id"`
	CallingStationID string `yaml:"calling_station_id"`
}

type EAP struct {
	MethodMismatchPolicy              string   `yaml:"method_mismatch_policy"`
	OuterIdentityUpdateOnPermanentReq *bool    `yaml:"outer_identity_update_on_permanent_req"`
	PermanentIDPolicy                 string   `yaml:"permanent_id_policy"`
	PermanentIdentityOverride         string   `yaml:"permanent_identity_override"`
	AKAPrime                          AKAPrime `yaml:"aka_prime"`
}

type AKAPrime struct {
	NetName string `yaml:"net_name"`
}

type SQN struct {
	Reset   bool  `yaml:"reset"`
	Persist *bool `yaml:"persist"`
}

type Expect struct {
	Result             string `yaml:"result"`
	RejectHintContains string `yaml:"reject_hint_contains"`
	MPPE               MPPE   `yaml:"mppe"`
}

type MPPE struct {
	RequirePresent *bool  `yaml:"require_present"`
	SendKey        string `yaml:"send_key"`
	RecvKey        string `yaml:"recv_key"`
}

type Trace struct {
	Level           string `yaml:"level"`
	UnsafeLog       bool   `yaml:"unsafe_log"`
	DumpEAPHex      *bool  `yaml:"dump_eap_hex"`
	DumpRadiusAttrs *bool  `yaml:"dump_radius_attrs"`
	SavePath        string `yaml:"save_path"`
}

// Validate checks the schema constraints defined in docs/TESTCASE_SCHEMA.md.
func (c Case) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("testcase: version must be 1")
	}
	if strings.TrimSpace(c.Identity) == "" {
		return fmt.Errorf("testcase: identity is required")
	}
	switch c.Expect.Result {
	case "accept", "reject":
	default:
		return fmt.Errorf("testcase: expect.result must be accept or reject")
	}
	if c.EAP.MethodMismatchPolicy != "" && !isOneOf(c.EAP.MethodMismatchPolicy, "strict", "warn", "allow") {
		return fmt.Errorf("testcase: eap.method_mismatch_policy must be strict, warn, or allow")
	}
	if c.EAP.PermanentIDPolicy != "" && !isOneOf(c.EAP.PermanentIDPolicy, "always", "conservative", "deny") {
		return fmt.Errorf("testcase: eap.permanent_id_policy must be always, conservative, or deny")
	}
	if c.Trace.Level != "" && !isOneOf(c.Trace.Level, "normal", "verbose") {
		return fmt.Errorf("testcase: trace.level must be normal or verbose")
	}
	if c.Expect.MPPE.SendKey != "" && !hasKeyPrefix(c.Expect.MPPE.SendKey) {
		return fmt.Errorf("testcase: expect.mppe.send_key must start with hex: or b64:")
	}
	if c.Expect.MPPE.RecvKey != "" && !hasKeyPrefix(c.Expect.MPPE.RecvKey) {
		return fmt.Errorf("testcase: expect.mppe.recv_key must start with hex: or b64:")
	}
	return nil
}

func hasKeyPrefix(v string) bool {
	return strings.HasPrefix(v, "hex:") || strings.HasPrefix(v, "b64:")
}

func isOneOf(value string, allowed ...string) bool {
	for _, v := range allowed {
		if value == v {
			return true
		}
	}
	return false
}
