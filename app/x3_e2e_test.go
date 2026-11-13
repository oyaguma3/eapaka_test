package app

import (
	"slices"
	"testing"

	"github.com/oyaguma3/eapaka_test/internal/fakeserver"

	eapaka "github.com/oyaguma3/go-eapaka"
)

// lastAKASubtype は、疑似サーバが最後に受け取った EAP-AKA/AKA' の応答の Subtype を返す。
func lastAKASubtype(srv *fakeserver.Server) uint8 {
	evs := srv.Events()
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Type == eapaka.TypeAKA || evs[i].Type == eapaka.TypeAKAPrime {
			return evs[i].Subtype
		}
	}
	return 0
}

// TestE2EPeerBehavior は X3（既存処理の RFC との差分修正）のピアの動作を確かめる。
func TestE2EPeerBehavior(t *testing.T) {
	tests := []struct {
		name        string
		cfg         fakeserver.Config
		emptyKdf    string // testcase の eap.aka_prime.empty_kdf_input
		expect      string
		wantSubtype uint8    // ピアが最後に送った応答の Subtype
		wantRules   []string // 記録されるべき違反
		wantExit    int
	}{
		{
			name: "KDF negotiation then success",
			cfg:  fakeserver.Config{Method: eapaka.TypeAKAPrime, KDFOffer: []uint16{2, 1}},
			// AT_KDF だけの応答 → 再提示 → 通常の応答
			expect: "accept", wantSubtype: eapaka.SubtypeChallenge, wantExit: 0,
		},
		{
			name:   "bad KDF re-offer",
			cfg:    fakeserver.Config{Method: eapaka.TypeAKAPrime, KDFOffer: []uint16{2, 1}, Faults: fakeserver.Faults{BadKdfReoffer: true}},
			expect: "reject", wantSubtype: eapaka.SubtypeClientError, wantRules: []string{"A-17"}, wantExit: 1,
		},
		{
			name:   "no supported KDF",
			cfg:    fakeserver.Config{Method: eapaka.TypeAKAPrime, KDFOffer: []uint16{2}},
			expect: "reject", wantSubtype: eapaka.SubtypeAuthenticationReject, wantExit: 0,
		},
		{
			name:   "wrong AUTN",
			cfg:    fakeserver.Config{Faults: fakeserver.Faults{WrongAUTN: true}},
			expect: "reject", wantSubtype: eapaka.SubtypeAuthenticationReject, wantExit: 0,
		},
		{
			name:   "invalid AT_MAC",
			cfg:    fakeserver.Config{Method: eapaka.TypeAKAPrime, Faults: fakeserver.Faults{CorruptRequestMAC: true}},
			expect: "reject", wantSubtype: eapaka.SubtypeClientError, wantRules: []string{"A-18"}, wantExit: 1,
		},
		{
			name:   "AKA' separation bit cleared",
			cfg:    fakeserver.Config{Method: eapaka.TypeAKAPrime, Faults: fakeserver.Faults{ClearSeparationBit: true}},
			expect: "reject", wantSubtype: eapaka.SubtypeAuthenticationReject, wantRules: []string{"A-12"}, wantExit: 1,
		},
		{
			name:   "AKA ignores the separation bit",
			cfg:    fakeserver.Config{Faults: fakeserver.Faults{ClearSeparationBit: true}},
			expect: "accept", wantSubtype: eapaka.SubtypeChallenge, wantExit: 0,
		},
		{
			name:   "empty AT_KDF_INPUT is rejected",
			cfg:    fakeserver.Config{Method: eapaka.TypeAKAPrime, Faults: fakeserver.Faults{EmptyKdfInput: true}},
			expect: "reject", wantSubtype: eapaka.SubtypeAuthenticationReject, wantRules: []string{"A-13"}, wantExit: 1,
		},
		{
			name:     "empty AT_KDF_INPUT with fallback",
			cfg:      fakeserver.Config{Method: eapaka.TypeAKAPrime, Faults: fakeserver.Faults{EmptyKdfInput: true}},
			emptyKdf: "fallback",
			// 認証は通るが、違反は記録されて exit 1
			expect: "accept", wantSubtype: eapaka.SubtypeChallenge, wantRules: []string{"A-13"}, wantExit: 1,
		},
		{
			name:   "unknown non-skippable attribute",
			cfg:    fakeserver.Config{Faults: fakeserver.Faults{UnknownNonSkippable: true}},
			expect: "reject", wantSubtype: eapaka.SubtypeClientError, wantRules: []string{"A-16"}, wantExit: 1,
		},
		{
			name: "non-zero reserved fields with a valid MAC",
			cfg:  fakeserver.Config{Method: eapaka.TypeAKAPrime, Faults: fakeserver.Faults{NonZeroReserved: true}},
			// 受信したバイト列のまま MAC を検証するので、認証は通る
			expect: "accept", wantSubtype: eapaka.SubtypeChallenge, wantExit: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startServer(t, tt.cfg)
			identity := "0440100123456789@" + e2eRealm
			if tt.cfg.Method == eapaka.TypeAKAPrime {
				identity = "6440100123456789@" + e2eRealm
			}
			tc := e2eCase(t, identity, tt.expect)
			tc.EAP.AKAPrime.EmptyKdfInput = tt.emptyKdf
			res := Run(t.Context(), e2eConfig(srv), tc)

			if got := lastAKASubtype(srv); got != tt.wantSubtype {
				t.Errorf("last peer subtype = %d, want %d", got, tt.wantSubtype)
			}
			ids := violationIDs(res.Violations)
			for _, id := range tt.wantRules {
				if !slices.Contains(ids, id) {
					t.Errorf("violations = %v, want %s", ids, id)
				}
			}
			if len(tt.wantRules) == 0 && len(ids) != 0 {
				t.Errorf("unexpected violations %v", ids)
			}
			if res.ExitCode != tt.wantExit {
				t.Errorf("exit = %d, want %d (err=%v)", res.ExitCode, tt.wantExit, res.Err)
			}
		})
	}
}

// TestE2EPermanentIDDenied は、永続 ID の要求を断るときに Client-Error を返すことを確かめる。
func TestE2EPermanentIDDenied(t *testing.T) {
	srv := startServer(t, fakeserver.Config{IdentityRequest: "permanent"})
	cfg := e2eConfig(srv)
	cfg.EAP.PermanentIDPolicy = "deny"
	res := Run(t.Context(), cfg, e2eCase(t, "2pseudonym@"+e2eRealm, "reject"))
	if got := lastAKASubtype(srv); got != eapaka.SubtypeClientError {
		t.Errorf("last peer subtype = %d, want Client-Error", got)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit = %d, want 0 (err=%v)", res.ExitCode, res.Err)
	}
}
