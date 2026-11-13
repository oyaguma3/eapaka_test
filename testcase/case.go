package testcase

import (
	"fmt"
	"slices"
	"strings"

	"github.com/oyaguma3/eapaka_test/conformance"
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

	Conformance Conformance `yaml:"conformance"`
	Faults      []Fault     `yaml:"fault"`
}

// Fault はピアに注入する異常（設計書 §6.4、X4）。
type Fault struct {
	At     string `yaml:"at"`
	Action string `yaml:"action"`
}

// faultActions は注入位置ごとに使える動作。
var faultActions = map[string][]string{
	"identity_response":  {"client_error", "auth_reject"},
	"challenge_response": {"corrupt_mac", "wrong_res", "client_error", "auth_reject"},
}

// Conformance はケース単位の準拠性ポリシーの上書き（設計書 §7.2）。
// 値は fail / warn / off。
type Conformance struct {
	Rules map[string]string `yaml:"rules"`
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
	NetName       string `yaml:"net_name"`
	NetNameCheck  string `yaml:"net_name_check"`
	EmptyKdfInput string `yaml:"empty_kdf_input"`
}

type SQN struct {
	Reset   bool  `yaml:"reset"`
	Persist *bool `yaml:"persist"`
}

type Expect struct {
	Result                  string `yaml:"result"`
	RejectHintContains      string `yaml:"reject_hint_contains"`
	RejectHintCheckPresence *bool  `yaml:"reject_hint_check_presence"`
	MPPE                    MPPE   `yaml:"mppe"`
}

type MPPE struct {
	RequirePresent *bool `yaml:"require_present"`
	// VerifyMSK は、MS-MPPE 鍵を復号した値がピアの MSK と一致することを求める（X2）。
	VerifyMSK bool   `yaml:"verify_msk"`
	SendKey   string `yaml:"send_key"`
	RecvKey   string `yaml:"recv_key"`
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
	if c.EAP.AKAPrime.NetNameCheck != "" && !isOneOf(c.EAP.AKAPrime.NetNameCheck, "off", "warn", "reject") {
		return fmt.Errorf("testcase: eap.aka_prime.net_name_check must be off, warn, or reject")
	}
	if c.EAP.AKAPrime.EmptyKdfInput != "" && !isOneOf(c.EAP.AKAPrime.EmptyKdfInput, "reject", "fallback") {
		return fmt.Errorf("testcase: eap.aka_prime.empty_kdf_input must be reject or fallback")
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
	for i, f := range c.Faults {
		actions, ok := faultActions[f.At]
		if !ok {
			return fmt.Errorf("testcase: fault[%d].at must be identity_response or challenge_response", i)
		}
		if !slices.Contains(actions, f.Action) {
			return fmt.Errorf("testcase: fault[%d].action %q cannot be used at %s (allowed: %s)", i, f.Action, f.At, strings.Join(actions, ", "))
		}
	}
	for id, v := range c.Conformance.Rules {
		if _, ok := conformance.Lookup(id); !ok {
			return fmt.Errorf("testcase: conformance.rules: unknown rule %q", id)
		}
		if _, err := conformance.ParseAction(v); err != nil {
			return fmt.Errorf("testcase: conformance.rules: rule %s: %w", id, err)
		}
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
