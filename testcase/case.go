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
	// IdentitySource は開始時の ID の選び方（設計書 §5.3）。literal（既定。identity をそのまま使う）、
	// permanent（IMSI とレルムから作る）、pseudonym（保存済みの仮名）、auto（仮名 → 永続 ID）。
	IdentitySource string `yaml:"identity_source"`
	// Method は、identity_source が literal 以外のときに使う ID のメソッド（aka / aka_prime。既定 aka）。
	Method string `yaml:"method"`
	// IdentityStore はケース単位の識別子ストアの扱い。
	IdentityStore IdentityStoreUse `yaml:"identity_store"`

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
	MethodPreference                  []uint8  `yaml:"method_preference"`
	Nak                               Nak      `yaml:"nak"`
	BiddingPolicy                     string   `yaml:"bidding_policy"`
	ResultInd                         *bool    `yaml:"result_ind"`
	Checkcode                         string   `yaml:"checkcode"`
}

// IdentityStoreUse は、ケースでの識別子ストアの扱い。
type IdentityStoreUse struct {
	// Reset は、実行の前にこの IMSI の記録を消す。
	Reset bool `yaml:"reset"`
	// Persist は、受け取った仮名を保存するか（既定 true）。
	Persist *bool `yaml:"persist"`
}

// Nak はケース単位の強制 Nak（X5）。
type Nak struct {
	On      []uint8 `yaml:"on"`
	Propose []uint8 `yaml:"propose"`
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
	Result                  string       `yaml:"result"`
	RejectHintContains      string       `yaml:"reject_hint_contains"`
	RejectHintCheckPresence *bool        `yaml:"reject_hint_check_presence"`
	MPPE                    MPPE         `yaml:"mppe"`
	Bidding                 Bidding      `yaml:"bidding"`
	Notification            Notification `yaml:"notification"`
	// NextPseudonym・NextReauthID は、AT_ENCR_DATA で次回の仮名・再認証 ID を受け取るか（present / absent）。
	NextPseudonym string `yaml:"next_pseudonym"`
	NextReauthID  string `yaml:"next_reauth_id"`
	// IdentityRequests は、受け取る AKA-Identity の要求の種類の並び（any / fullauth / permanent / none）。
	IdentityRequests []string `yaml:"identity_requests"`
	// Checkcode は AT_CHECKCODE の検証結果（verified / absent）。
	Checkcode string `yaml:"checkcode"`
}

// Notification は AKA-Notification の期待値（RFC 4187 §6）。省略した項目は検査しない。
type Notification struct {
	// Code は受け取るべき通知のコード値（S・P ビットを含む。例: 32768 は成功、16384 は認証前の失敗）。
	Code *uint16 `yaml:"code"`
	// Present は通知を受け取ったかどうか。
	Present *bool `yaml:"present"`
}

// Bidding は AT_BIDDING の期待値（RFC 9048 §4）。省略した項目は検査しない。
type Bidding struct {
	Present *bool  `yaml:"present"`
	DBit    *bool  `yaml:"d_bit"`
	Action  string `yaml:"action"` // reject / ignore
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
	switch c.IdentitySource {
	case "", "literal":
		if strings.TrimSpace(c.Identity) == "" {
			return fmt.Errorf("testcase: identity is required")
		}
	case "permanent", "pseudonym", "auto":
	default:
		return fmt.Errorf("testcase: identity_source must be literal, permanent, pseudonym, or auto")
	}
	if c.Method != "" && !isOneOf(c.Method, "aka", "aka_prime") {
		return fmt.Errorf("testcase: method must be aka or aka_prime")
	}
	if c.EAP.Checkcode != "" && !isOneOf(c.EAP.Checkcode, "auto", "always", "never") {
		return fmt.Errorf("testcase: eap.checkcode must be auto, always, or never")
	}
	for _, v := range []string{c.Expect.NextPseudonym, c.Expect.NextReauthID} {
		if v != "" && !isOneOf(v, "present", "absent") {
			return fmt.Errorf("testcase: expect.next_pseudonym and expect.next_reauth_id must be present or absent")
		}
	}
	if c.Expect.Checkcode != "" && !isOneOf(c.Expect.Checkcode, "verified", "absent") {
		return fmt.Errorf("testcase: expect.checkcode must be verified or absent")
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
	for _, m := range append(slices.Clone(c.EAP.MethodPreference), c.EAP.Nak.On...) {
		if m != 23 && m != 50 {
			return fmt.Errorf("testcase: eap.method_preference and eap.nak.on accept only 23 and 50, got %d", m)
		}
	}
	if c.EAP.BiddingPolicy != "" && !isOneOf(c.EAP.BiddingPolicy, "reject", "ignore") {
		return fmt.Errorf("testcase: eap.bidding_policy must be reject or ignore")
	}
	if c.Expect.Bidding.Action != "" && !isOneOf(c.Expect.Bidding.Action, "reject", "ignore") {
		return fmt.Errorf("testcase: expect.bidding.action must be reject or ignore")
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
