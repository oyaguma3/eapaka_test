package app

import (
	"slices"
	"testing"

	"github.com/oyaguma3/eapaka_test/conformance"
	"github.com/oyaguma3/eapaka_test/internal/fakeserver"

	eapaka "github.com/oyaguma3/go-eapaka"
)

func violationIDs(vs []conformance.Violation) []string {
	var ids []string
	for _, v := range vs {
		ids = append(ids, v.Rule.ID)
	}
	return ids
}

// TestE2ERadiusRules は、疑似サーバに注入した RADIUS/EAP 層の違反（R-01〜R-07）を
// チェッカが検出できることを確かめる。
func TestE2ERadiusRules(t *testing.T) {
	tests := []struct {
		name     string
		method   uint8
		faults   fakeserver.Faults
		expect   string // テストケースの期待結果
		wantRule string
		wantExit int // MUST は fail（exit 1）、SHOULD は warn（exit 0）
	}{
		{"R-01 corrupt Message-Authenticator", eapaka.TypeAKA, fakeserver.Faults{CorruptMessageAuthenticator: true}, "accept", "R-01", 1},
		{"R-02 omit Message-Authenticator", eapaka.TypeAKA, fakeserver.Faults{OmitMessageAuthenticator: true}, "accept", "R-02", 0},
		{"R-03a Accept without EAP", eapaka.TypeAKA, fakeserver.Faults{AcceptWithoutEAP: true}, "accept", "R-03a", 0},
		{"R-03a Accept with EAP-Failure", eapaka.TypeAKAPrime, fakeserver.Faults{AcceptWithEAPFailure: true}, "accept", "R-03a", 0},
		{"R-03b Challenge without EAP", eapaka.TypeAKA, fakeserver.Faults{ChallengeWithoutEAP: true}, "accept", "R-03b", 1},
		{"R-04 wrong Success Identifier", eapaka.TypeAKA, fakeserver.Faults{WrongSuccessIdentifier: true}, "accept", "R-04", 1},
		{"R-05 early Accept", eapaka.TypeAKA, fakeserver.Faults{EarlyAccept: true}, "accept", "R-05", 1},
		{"R-05 EAP-Success after Authentication-Reject", eapaka.TypeAKA, fakeserver.Faults{WrongAUTN: true, RejectWithEAPSuccess: true}, "reject", "R-05", 1},
		{"R-06 method switch", eapaka.TypeAKA, fakeserver.Faults{SwitchMethod: true}, "reject", "R-06", 1},
		{"R-07 Salt MSB clear", eapaka.TypeAKA, fakeserver.Faults{MPPESaltMSBClear: true}, "accept", "R-07", 1},
		{"R-07 duplicate Salt", eapaka.TypeAKAPrime, fakeserver.Faults{MPPEDuplicateSalt: true}, "accept", "R-07", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startServer(t, fakeserver.Config{Method: tt.method, Faults: tt.faults})
			identity := "0440100123456789@" + e2eRealm
			if tt.method == eapaka.TypeAKAPrime {
				identity = "6440100123456789@" + e2eRealm
			}
			res := Run(t.Context(), e2eConfig(srv), e2eCase(t, identity, tt.expect))
			ids := violationIDs(res.Violations)
			if !slices.Contains(ids, tt.wantRule) {
				t.Fatalf("violations = %v, want %s (err=%v)", ids, tt.wantRule, res.Err)
			}
			if res.ExitCode != tt.wantExit {
				t.Errorf("exit = %d, want %d (err=%v)", res.ExitCode, tt.wantExit, res.Err)
			}
		})
	}
}

func TestE2ENoViolations(t *testing.T) {
	for _, method := range []uint8{eapaka.TypeAKA, eapaka.TypeAKAPrime} {
		srv := startServer(t, fakeserver.Config{Method: method})
		res := Run(t.Context(), e2eConfig(srv), e2eCase(t, "0440100123456789@"+e2eRealm, "accept"))
		if res.ExitCode != 0 || len(res.Violations) != 0 {
			t.Errorf("method %d: exit = %d, violations = %v, err = %v", method, res.ExitCode, violationIDs(res.Violations), res.Err)
		}
	}
}

// TestE2EConformancePolicy は、ケース単位の上書きで規則の扱いを変えられることを確かめる。
func TestE2EConformancePolicy(t *testing.T) {
	srv := startServer(t, fakeserver.Config{Faults: fakeserver.Faults{OmitMessageAuthenticator: true, WrongSuccessIdentifier: true}})
	tc := e2eCase(t, "0440100123456789@"+e2eRealm, "accept")
	tc.Conformance.Rules = map[string]string{"R-02": "fail", "R-04": "off"}
	res := Run(t.Context(), e2eConfig(srv), tc)
	ids := violationIDs(res.Violations)
	if slices.Contains(ids, "R-04") || !slices.Contains(ids, "R-02") {
		t.Fatalf("violations = %v, want R-02 only", ids)
	}
	if res.ExitCode != 1 {
		t.Errorf("exit = %d, want 1", res.ExitCode)
	}
}
