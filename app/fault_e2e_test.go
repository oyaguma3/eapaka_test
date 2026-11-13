package app

import (
	"slices"
	"testing"

	"github.com/oyaguma3/eapaka_test/internal/fakeserver"
	"github.com/oyaguma3/eapaka_test/testcase"

	eapaka "github.com/oyaguma3/go-eapaka"
)

// TestE2EFaultInjection は X4 の異常系注入で、サーバが期待どおり拒否することを確かめる。
func TestE2EFaultInjection(t *testing.T) {
	tests := []struct {
		name        string
		cfg         fakeserver.Config
		fault       testcase.Fault
		wantSubtype uint8
	}{
		{"corrupt_mac", fakeserver.Config{}, testcase.Fault{At: "challenge_response", Action: "corrupt_mac"}, eapaka.SubtypeChallenge},
		{"wrong_res", fakeserver.Config{Method: eapaka.TypeAKAPrime}, testcase.Fault{At: "challenge_response", Action: "wrong_res"}, eapaka.SubtypeChallenge},
		{"client_error", fakeserver.Config{}, testcase.Fault{At: "challenge_response", Action: "client_error"}, eapaka.SubtypeClientError},
		{"auth_reject at identity", fakeserver.Config{IdentityRequest: "any"}, testcase.Fault{At: "identity_response", Action: "auth_reject"}, eapaka.SubtypeAuthenticationReject},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startServer(t, tt.cfg)
			identity := "0440100123456789@" + e2eRealm
			if tt.cfg.Method == eapaka.TypeAKAPrime {
				identity = "6440100123456789@" + e2eRealm
			}
			tc := e2eCase(t, identity, "reject")
			tc.Faults = []testcase.Fault{tt.fault}
			res := Run(t.Context(), e2eConfig(srv), tc)
			if res.ExitCode != 0 || len(res.Violations) != 0 {
				t.Fatalf("exit = %d, violations = %v, err = %v", res.ExitCode, violationIDs(res.Violations), res.Err)
			}
			if got := lastAKASubtype(srv); got != tt.wantSubtype {
				t.Errorf("last peer subtype = %d, want %d", got, tt.wantSubtype)
			}
			if want := tt.fault.At + "/" + tt.fault.Action; !slices.Contains(res.Obs.Faults, want) {
				t.Errorf("Obs.Faults = %v, want %s", res.Obs.Faults, want)
			}
		})
	}
}

// TestE2EFaultAcceptedByServer は、無効な応答を受け入れたサーバを R-05 で検出することを確かめる。
func TestE2EFaultAcceptedByServer(t *testing.T) {
	srv := startServer(t, fakeserver.Config{Faults: fakeserver.Faults{IgnoreResponseResult: true}})
	tc := e2eCase(t, "0440100123456789@"+e2eRealm, "reject")
	tc.Faults = []testcase.Fault{{At: "challenge_response", Action: "wrong_res"}}
	res := Run(t.Context(), e2eConfig(srv), tc)
	if !slices.Contains(violationIDs(res.Violations), "R-05") {
		t.Errorf("violations = %v, want R-05", violationIDs(res.Violations))
	}
	if res.ExitCode != 1 {
		t.Errorf("exit = %d, want 1", res.ExitCode)
	}
}
