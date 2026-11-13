package conformance

import (
	"slices"
	"testing"
)

func TestPolicyActionFor(t *testing.T) {
	p := DefaultPolicy()
	p.Rules = map[string]Action{"R-02": ActionFail, "R-01": ActionOff}
	tests := []struct {
		id   string
		want Action
	}{
		{"R-01", ActionOff},   // 規則ごとの上書きが優先する
		{"R-02", ActionFail},  // SHOULD でも上書きできる
		{"R-03a", ActionWarn}, // SHOULD の既定値
		{"R-04", ActionFail},  // MUST の既定値
	}
	for _, tt := range tests {
		rule, ok := Lookup(tt.id)
		if !ok {
			t.Fatalf("rule %s not found", tt.id)
		}
		if got := p.ActionFor(rule); got != tt.want {
			t.Errorf("ActionFor(%s) = %s, want %s", tt.id, got, tt.want)
		}
	}
}

func TestRecorder(t *testing.T) {
	p := DefaultPolicy()
	p.Rules = map[string]Action{"R-01": ActionOff}
	r := NewRecorder(p)
	var reported []string
	r.OnReport = func(v Violation) { reported = append(reported, v.Rule.ID) }

	r.SetRound(2)
	r.Report("R-01", "ignored")
	r.Report("R-02", "missing %s", "Message-Authenticator")
	if r.Failed() {
		t.Fatal("Failed() = true with only a warn violation")
	}
	r.Report("R-04", "id mismatch")
	r.Report("R-04", "id mismatch again")

	if !r.Failed() {
		t.Error("Failed() = false after a fail violation")
	}
	if got, want := r.FailedIDs(), []string{"R-04"}; !slices.Equal(got, want) {
		t.Errorf("FailedIDs() = %v, want %v", got, want)
	}
	if !slices.Equal(reported, []string{"R-02", "R-04", "R-04"}) {
		t.Errorf("OnReport got %v", reported)
	}
	vs := r.Violations()
	if len(vs) != 3 || vs[0].Detail != "missing Message-Authenticator" || vs[0].Round != 2 {
		t.Errorf("Violations() = %+v", vs)
	}
	if r.Has("R-01") || !r.Has("R-02") {
		t.Error("Has() reports wrong rules")
	}
}

func TestNilRecorder(t *testing.T) {
	var r *Recorder
	r.SetRound(1)
	r.Report("R-01", "x")
	if r.Failed() || r.Has("R-01") || r.Violations() != nil {
		t.Error("nil Recorder must be a no-op")
	}
}

func TestParseAction(t *testing.T) {
	for _, s := range []string{"fail", "warn", "off"} {
		if _, err := ParseAction(s); err != nil {
			t.Errorf("ParseAction(%q) error: %v", s, err)
		}
	}
	if _, err := ParseAction("error"); err == nil {
		t.Error("ParseAction(error) succeeded")
	}
}
