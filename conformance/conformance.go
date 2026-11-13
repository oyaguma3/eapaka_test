// Package conformance は、テスト対象サーバの RFC 違反を記録する（設計書 §6.1、X1）。
//
// 規則ごとに ID・RFC の参照・レベル（MUST/SHOULD）を持ち、ポリシーで
// fail / warn / off のどれとして扱うかを決める。fail の違反が 1 件でもあれば、
// 期待結果と一致していても実行は FAIL（exit 1）になる。
package conformance

import (
	"fmt"
	"maps"
	"slices"
)

// Level は RFC の要求レベル。
type Level string

const (
	MUST   Level = "MUST"
	SHOULD Level = "SHOULD"
)

// Action は違反をどう扱うか。
type Action string

const (
	ActionFail Action = "fail"
	ActionWarn Action = "warn"
	ActionOff  Action = "off"
)

// ParseAction は設定値を Action に変換する。
func ParseAction(s string) (Action, error) {
	switch a := Action(s); a {
	case ActionFail, ActionWarn, ActionOff:
		return a, nil
	default:
		return "", fmt.Errorf("conformance: action must be fail, warn, or off: %q", s)
	}
}

// Rule は準拠性の規則。
type Rule struct {
	ID    string
	Ref   string
	Level Level
	Desc  string
	// Default は、レベルごとの既定値の代わりに使う既定の扱い（推定による判定の規則など）。空ならレベルに従う。
	Default Action
}

// rules は規則の一覧（設計書 §6.1 の表）。Phase ごとに追加する。
var rules = map[string]Rule{
	"R-01":  {ID: "R-01", Ref: "RFC 3579 §3.2", Level: MUST, Desc: "Message-Authenticator in a response must be valid"},
	"R-02":  {ID: "R-02", Ref: "RFC 3579 §3.1", Level: SHOULD, Desc: "a response carrying EAP-Message should include Message-Authenticator"},
	"R-03a": {ID: "R-03a", Ref: "RFC 3579 §2.6.3", Level: SHOULD, Desc: "Access-Accept should carry EAP-Success and Access-Reject EAP-Failure"},
	"R-03b": {ID: "R-03b", Ref: "RFC 3579 §2.1", Level: MUST, Desc: "Access-Challenge must carry an EAP-Request"},
	"R-04":  {ID: "R-04", Ref: "RFC 3748 §4.2", Level: MUST, Desc: "EAP-Success/Failure Identifier must match the last EAP-Response"},
	"R-05":  {ID: "R-05", Ref: "RFC 3748 §4.2, RFC 4187 §6.2", Level: MUST, Desc: "no success indication before the method completes or after it failed"},
	"R-06":  {ID: "R-06", Ref: "RFC 3748 §2.1", Level: MUST, Desc: "the server must not switch EAP methods during a method"},
	"R-08":  {ID: "R-08", Ref: "RFC 3748 §5.3.1", Level: SHOULD, Desc: "the server should not send another Request after a Nak with type 0"},
	"R-09":  {ID: "R-09", Ref: "RFC 7268 §2.2, RFC 5247", Level: MUST, Desc: "EAP-Key-Name in Access-Accept must contain the EAP Session-Id"},
	"R-10":  {ID: "R-10", Ref: "RFC 7268 §2.2", Level: SHOULD, Desc: "the server should include EAP-Key-Name only when the Access-Request carried one"},
	"R-07":  {ID: "R-07", Ref: "RFC 2548 §2.4.2", Level: MUST, Desc: "MS-MPPE key Salt must have the MSB set and be unique within an Access-Accept"},
	"A-01":  {ID: "A-01", Ref: "RFC 4187 §4.1.5, §9.1", Level: MUST, Desc: "at most 3 AKA-Identity rounds, AT_ANY_ID_REQ only in the first, no identity request after AT_PERMANENT_ID_REQ"},
	"A-02":  {ID: "A-02", Ref: "RFC 4187 §10.12", Level: MUST, Desc: "AT_IV must not be reused"},
	"A-03":  {ID: "A-03", Ref: "RFC 4187 §10.18", Level: MUST, Desc: "AT_NONCE_S must not be reused"},
	"A-04":  {ID: "A-04", Ref: "RFC 4187 §5.1, §5.4", Level: MUST, Desc: "AT_COUNTER must be greater than in earlier re-authentications"},
	"A-05":  {ID: "A-05", Ref: "RFC 4187 §10.12", Level: MUST, Desc: "AT_ENCR_DATA must be a multiple of 16 bytes and AT_PADDING must be zero-filled and last"},
	"A-06":  {ID: "A-06", Ref: "RFC 4187 §10.10, §10.11", Level: MUST, Desc: "AT_NEXT_PSEUDONYM has no realm, and AT_NEXT_PSEUDONYM / AT_NEXT_REAUTH_ID are only sent encrypted"},
	"A-07":  {ID: "A-07", Ref: "RFC 4187 §10.14", Level: MUST, Desc: "AT_RESULT_IND must not be included in AT_ENCR_DATA"},
	"A-08":  {ID: "A-08", Ref: "RFC 4187 §6.1, §6.2", Level: MUST, Desc: "AKA-Notification: S=0 when P=1, P=0 only after successful authentication, one round per exchange, success only with AT_RESULT_IND"},
	"A-09":  {ID: "A-09", Ref: "RFC 9048 §4", Level: MUST, Desc: "AT_BIDDING must not be included in EAP-AKA' messages"},
	"A-10":  {ID: "A-10", Ref: "RFC 4187 §6.3.1", Level: MUST, Desc: "after the peer's Client-Error or Authentication-Reject the server must send EAP-Failure"},
	"A-11":  {ID: "A-11", Ref: "RFC 4187 §5.5", Level: MUST, Desc: "after AT_COUNTER_TOO_SMALL the server must send a Challenge without AKA-Identity"},
	"A-12":  {ID: "A-12", Ref: "RFC 9048 §3.3", Level: MUST, Desc: "the AMF separation bit in EAP-AKA' AUTN must be 1"},
	"A-13":  {ID: "A-13", Ref: "RFC 9048 §3.1", Level: MUST, Desc: "AT_KDF_INPUT must be present with a non-empty network name"},
	"A-14":  {ID: "A-14", Ref: "RFC 9048 §5.2", Level: MUST, Default: ActionWarn, Desc: "EAP-AKA' pseudonyms must not reveal the IMSI (heuristic, warn by default)"},
	"A-15":  {ID: "A-15", Ref: "RFC 4187 §8.1, §10", Level: SHOULD, Desc: "reserved fields are set to zero when sending (the RFC uses no MUST/SHOULD keyword, so this is SHOULD)"},
	"A-16":  {ID: "A-16", Ref: "RFC 4187 §6.3.1, §8.1", Level: MUST, Desc: "EAP-AKA/AKA' requests must be well-formed (known subtype, no unknown non-skippable attribute, required attributes present)"},
	"A-17":  {ID: "A-17", Ref: "RFC 9048 §3.2", Level: MUST, Desc: "an AT_KDF re-offer must prepend the selected KDF to the original offer"},
	"A-18":  {ID: "A-18", Ref: "RFC 4187 §10.15", Level: MUST, Desc: "AT_MAC in a request must be present and valid"},
	"A-19":  {ID: "A-19", Ref: "RFC 4187 §10.13, RFC 9048 §3.4.3", Level: MUST, Desc: "AT_CHECKCODE must match the AKA-Identity messages exchanged"},
}

// Lookup は ID の規則を返す。
func Lookup(id string) (Rule, bool) {
	r, ok := rules[id]
	return r, ok
}

// IDs は登録済みの規則の ID を整列して返す。
func IDs() []string {
	return slices.Sorted(maps.Keys(rules))
}

// Policy は規則の扱い。Rules は規則ごとの上書きで、レベルごとの既定値より優先する。
type Policy struct {
	DefaultMust   Action
	DefaultShould Action
	Rules         map[string]Action
}

// DefaultPolicy は MUST を fail、SHOULD を warn にする（設計書 §6.1）。
func DefaultPolicy() Policy {
	return Policy{DefaultMust: ActionFail, DefaultShould: ActionWarn}
}

// ActionFor は規則の扱いを返す。
func (p Policy) ActionFor(r Rule) Action {
	if a, ok := p.Rules[r.ID]; ok {
		return a
	}
	if r.Default != "" {
		return r.Default
	}
	if r.Level == MUST {
		return p.DefaultMust
	}
	return p.DefaultShould
}

// Violation は記録した違反。
type Violation struct {
	Rule   Rule
	Action Action
	Detail string
	Round  int // 何回目の RADIUS 交換か（1 から数える）
}

// Recorder は違反を記録する。nil の Recorder の Report は何もしない。
type Recorder struct {
	policy     Policy
	round      int
	violations []Violation

	// OnReport は違反を記録するたびに呼ばれる（トレースへの出力用）。
	OnReport func(Violation)
}

// NewRecorder はポリシーを指定して Recorder を作る。
func NewRecorder(p Policy) *Recorder {
	return &Recorder{policy: p}
}

// SetRound は現在の RADIUS 交換の回数を設定する。
func (r *Recorder) SetRound(n int) {
	if r != nil {
		r.round = n
	}
}

// Report は違反を記録する。ポリシーで off の規則は記録しない。
// 未登録の ID はプログラムの誤りなので panic する。
func (r *Recorder) Report(id, format string, args ...any) {
	if r == nil {
		return
	}
	rule, ok := rules[id]
	if !ok {
		panic("conformance: unknown rule " + id)
	}
	action := r.policy.ActionFor(rule)
	if action == ActionOff {
		return
	}
	v := Violation{Rule: rule, Action: action, Detail: fmt.Sprintf(format, args...), Round: r.round}
	r.violations = append(r.violations, v)
	if r.OnReport != nil {
		r.OnReport(v)
	}
}

// Violations は記録した違反を返す。
func (r *Recorder) Violations() []Violation {
	if r == nil {
		return nil
	}
	return slices.Clone(r.violations)
}

// Has は ID の違反が記録されているかを返す。
func (r *Recorder) Has(id string) bool {
	if r == nil {
		return false
	}
	return slices.ContainsFunc(r.violations, func(v Violation) bool { return v.Rule.ID == id })
}

// Failed は fail の違反が 1 件でもあるかを返す。
func (r *Recorder) Failed() bool {
	if r == nil {
		return false
	}
	return slices.ContainsFunc(r.violations, func(v Violation) bool { return v.Action == ActionFail })
}

// FailedIDs は fail の違反の規則 ID を、重複を除いて記録順に返す。
func (r *Recorder) FailedIDs() []string {
	var ids []string
	for _, v := range r.Violations() {
		if v.Action == ActionFail && !slices.Contains(ids, v.Rule.ID) {
			ids = append(ids, v.Rule.ID)
		}
	}
	return ids
}
