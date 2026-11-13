package app

import (
	"slices"
	"testing"

	"github.com/oyaguma3/eapaka_test/config"
	"github.com/oyaguma3/eapaka_test/internal/fakeserver"
	"github.com/oyaguma3/eapaka_test/testcase"

	eapaka "github.com/oyaguma3/go-eapaka"
)

// reauthSetup は、再認証 ID を発行する疑似サーバと、識別子ストアをファイルに置いた設定を用意し、
// フル認証を 1 回行って再認証 ID を保存する。
func reauthSetup(t *testing.T, scfg fakeserver.Config, method string) config.Config {
	t.Helper()
	if scfg.IssueReauthID == "" {
		scfg.IssueReauthID = map[string]string{"aka": "4re", "aka_prime": "8re"}[method]
	}
	srv := startServer(t, scfg)
	cfg := fileIDStore(t, e2eConfig(srv))
	tc := e2eCase(t, "", "accept")
	tc.IdentitySource, tc.Method = "permanent", method
	tc.Expect.NextReauthID, tc.Expect.AuthType = "present", "full"
	if res := Run(t.Context(), cfg, tc); res.ExitCode != 0 {
		t.Fatalf("full authentication: exit = %d, err = %v", res.ExitCode, res.Err)
	}
	return cfg
}

func reauthCase(t *testing.T, method, expect string) testcase.Case {
	tc := e2eCase(t, "", expect)
	tc.IdentitySource, tc.Method = "reauth", method
	return tc
}

// TestE2EReauthChain は、フル認証 → 再認証 → 再認証の連鎖と、再認証での MSK 照合を確かめる。
func TestE2EReauthChain(t *testing.T) {
	for _, m := range []struct {
		method  string
		eapType uint8
	}{{"aka", eapaka.TypeAKA}, {"aka_prime", eapaka.TypeAKAPrime}} {
		t.Run(m.method, func(t *testing.T) {
			cfg := reauthSetup(t, fakeserver.Config{Method: m.eapType}, m.method)
			for i, want := range []uint16{1, 2} {
				tc := reauthCase(t, m.method, "accept")
				tc.Expect.AuthType, tc.Expect.NextReauthID = "reauth", "present"
				tc.Expect.MPPE.VerifyMSK = true
				res := Run(t.Context(), cfg, tc)
				if res.ExitCode != 0 || res.Obs.ReauthCounter != want || len(res.Violations) != 0 {
					t.Fatalf("reauth %d: exit = %d, counter = %d, violations = %v, err = %v",
						i+1, res.ExitCode, res.Obs.ReauthCounter, violationIDs(res.Violations), res.Err)
				}
			}
		})
	}
}

// TestE2EReauthBehavior は、再認証の周辺の動作と規則（A-03、A-04、A-06、A-11）を確かめる。
func TestE2EReauthBehavior(t *testing.T) {
	tests := []struct {
		name      string
		cfg       fakeserver.Config
		reauths   int // 最後のケースの前に行う再認証の数
		faults    []testcase.Fault
		expect    string
		check     func(*testcase.Expect)
		wantRules []string
		wantExit  int
	}{
		{
			name:    "reused reauth identity leads to full authentication",
			cfg:     fakeserver.Config{},
			reauths: 1, faults: []testcase.Fault{{At: "start", Action: "reuse_reauth_id"}}, expect: "accept",
			check: func(e *testcase.Expect) { e.AuthType = "full"; e.IdentityRequests = []string{"fullauth"} },
		},
		{
			name:   "peer reports counter too small",
			cfg:    fakeserver.Config{},
			faults: []testcase.Fault{{At: "reauth_response", Action: "counter_too_small"}}, expect: "accept",
			check: func(e *testcase.Expect) { e.AuthType = "full"; e.CounterTooSmallSent = new(true) },
		},
		{
			name:   "wrong counter is rejected",
			cfg:    fakeserver.Config{},
			faults: []testcase.Fault{{At: "reauth_response", Action: "wrong_counter"}}, expect: "reject",
		},
		{
			name: "A-03 NONCE_S reused", cfg: fakeserver.Config{Faults: fakeserver.Faults{FixedNonceS: true}},
			reauths: 1, expect: "accept", wantRules: []string{"A-03"}, wantExit: 1,
		},
		{
			name: "A-04 counter not increased", cfg: fakeserver.Config{Faults: fakeserver.Faults{StaleCounter: true}},
			expect: "accept", wantRules: []string{"A-04"}, wantExit: 1,
			check: func(e *testcase.Expect) { e.CounterTooSmallSent = new(true) },
		},
		{
			name:   "A-11 AKA-Identity after counter too small",
			cfg:    fakeserver.Config{Faults: fakeserver.Faults{IdentityAfterCounterTooSmall: true}},
			faults: []testcase.Fault{{At: "reauth_response", Action: "counter_too_small"}}, expect: "accept",
			wantRules: []string{"A-11"}, wantExit: 1,
		},
		{
			name: "A-06 pseudonym in re-authentication", cfg: fakeserver.Config{Faults: fakeserver.Faults{PseudonymInReauth: true}},
			expect: "accept", wantRules: []string{"A-06"}, wantExit: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := reauthSetup(t, tt.cfg, "aka")
			for range tt.reauths {
				if res := Run(t.Context(), cfg, reauthCase(t, "aka", "accept")); res.ExitCode != 0 {
					t.Fatalf("preparatory reauth: exit = %d, err = %v", res.ExitCode, res.Err)
				}
			}
			tc := reauthCase(t, "aka", tt.expect)
			tc.Faults = tt.faults
			if tt.check != nil {
				tt.check(&tc.Expect)
			}
			res := Run(t.Context(), cfg, tc)
			ids := violationIDs(res.Violations)
			for _, id := range tt.wantRules {
				if !slices.Contains(ids, id) {
					t.Errorf("violations = %v, want %s (err=%v)", ids, id, res.Err)
				}
			}
			if len(tt.wantRules) == 0 && len(ids) > 0 {
				t.Errorf("unexpected violations %v", ids)
			}
			if res.ExitCode != tt.wantExit {
				t.Errorf("exit = %d, want %d (err=%v)", res.ExitCode, tt.wantExit, res.Err)
			}
		})
	}
}

// TestE2EReauthCrossMethod は、EAP-AKA の再認証コンテキストを EAP-AKA' で使わないことを確かめる（RFC 9048 §7）。
func TestE2EReauthCrossMethod(t *testing.T) {
	cfg := reauthSetup(t, fakeserver.Config{}, "aka")
	res := Run(t.Context(), cfg, reauthCase(t, "aka_prime", "accept"))
	if res.ExitCode != 2 {
		t.Errorf("exit = %d, want 2 (no EAP-AKA' context), err = %v", res.ExitCode, res.Err)
	}
}

// TestE2EFullauthPrefersPseudonym は、AT_FULLAUTH_ID_REQ に再認証 ID ではなく、
// 保存済みの仮名で答えることを確かめる（RFC 4187 §4.1.5）。
func TestE2EFullauthPrefersPseudonym(t *testing.T) {
	cfg := reauthSetup(t, fakeserver.Config{IssuePseudonym: "2pseudo77", KnownPseudonyms: []string{"2pseudo77"}}, "aka")
	if res := Run(t.Context(), cfg, reauthCase(t, "aka", "accept")); res.ExitCode != 0 {
		t.Fatalf("reauth: exit = %d, err = %v", res.ExitCode, res.Err)
	}
	tc := reauthCase(t, "aka", "accept")
	tc.Faults = []testcase.Fault{{At: "start", Action: "reuse_reauth_id"}}
	tc.Expect.AuthType, tc.Expect.IdentityRequests = "full", []string{"fullauth"}
	res := Run(t.Context(), cfg, tc)
	if res.ExitCode != 0 || res.Obs.PeerID != "2pseudo77@"+e2eRealm {
		t.Errorf("exit = %d, Peer-Id = %q, err = %v", res.ExitCode, res.Obs.PeerID, res.Err)
	}
}
