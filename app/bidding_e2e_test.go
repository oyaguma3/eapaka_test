package app

import (
	"slices"
	"testing"

	"github.com/oyaguma3/eapaka_test/internal/fakeserver"
	"github.com/oyaguma3/eapaka_test/testcase"

	eapaka "github.com/oyaguma3/go-eapaka"
)

// TestE2EBidding は AT_BIDDING（RFC 9048 §4）と強制 Nak（X5）を確かめる。
func TestE2EBidding(t *testing.T) {
	forceAKA := testcase.Nak{On: []uint8{eapaka.TypeAKAPrime}, Propose: []uint8{eapaka.TypeAKA}}
	tests := []struct {
		name        string
		cfg         fakeserver.Config
		nak         testcase.Nak
		policy      string
		expect      string
		bidding     testcase.Bidding
		wantSubtype uint8
		wantRules   []string
	}{
		{
			name: "reject on forced AKA",
			cfg:  fakeserver.Config{Method: eapaka.TypeAKAPrime, NakMethods: []uint8{eapaka.TypeAKA}, Bidding: "d1"},
			nak:  forceAKA, expect: "reject",
			bidding:     testcase.Bidding{Present: new(true), DBit: new(true), Action: "reject"},
			wantSubtype: eapaka.SubtypeAuthenticationReject,
		},
		{
			name: "ignore as an AKA-only peer",
			cfg:  fakeserver.Config{Method: eapaka.TypeAKAPrime, NakMethods: []uint8{eapaka.TypeAKA}, Bidding: "d1"},
			nak:  forceAKA, policy: "ignore", expect: "accept",
			bidding:     testcase.Bidding{Present: new(true), DBit: new(true), Action: "ignore"},
			wantSubtype: eapaka.SubtypeChallenge,
		},
		{
			name: "D bit clear",
			cfg:  fakeserver.Config{Bidding: "d0"}, expect: "accept",
			bidding:     testcase.Bidding{Present: new(true), DBit: new(false), Action: "ignore"},
			wantSubtype: eapaka.SubtypeChallenge,
		},
		{
			name: "no AT_BIDDING",
			cfg:  fakeserver.Config{}, expect: "accept",
			bidding:     testcase.Bidding{Present: new(false)},
			wantSubtype: eapaka.SubtypeChallenge,
		},
		{
			name:        "A-09 AT_BIDDING in EAP-AKA'",
			cfg:         fakeserver.Config{Method: eapaka.TypeAKAPrime, Faults: fakeserver.Faults{BiddingInAKAPrime: true}},
			expect:      "accept",
			bidding:     testcase.Bidding{Present: new(true)},
			wantSubtype: eapaka.SubtypeChallenge,
			wantRules:   []string{"A-09"},
		},
		{
			name:   "Nak refused by the server",
			cfg:    fakeserver.Config{Method: eapaka.TypeAKAPrime},
			nak:    forceAKA,
			expect: "reject",
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
			tc.EAP.Nak = tt.nak
			tc.EAP.BiddingPolicy = tt.policy
			tc.Expect.Bidding = tt.bidding
			if tt.expect == "accept" {
				tc.Expect.MPPE.VerifyMSK = true
			}
			res := Run(t.Context(), e2eConfig(srv), tc)

			wantExit := 0
			if len(tt.wantRules) > 0 {
				wantExit = 1
			}
			if res.ExitCode != wantExit {
				t.Errorf("exit = %d, want %d (err=%v)", res.ExitCode, wantExit, res.Err)
			}
			ids := violationIDs(res.Violations)
			for _, id := range tt.wantRules {
				if !slices.Contains(ids, id) {
					t.Errorf("violations = %v, want %s", ids, id)
				}
			}
			if len(tt.wantRules) == 0 && len(ids) > 0 {
				t.Errorf("unexpected violations %v", ids)
			}
			if tt.wantSubtype != 0 {
				if got := lastAKASubtype(srv); got != tt.wantSubtype {
					t.Errorf("last peer subtype = %d, want %d", got, tt.wantSubtype)
				}
			}
			if len(tt.nak.On) > 0 && len(res.Obs.Naks) != 1 {
				t.Errorf("Obs.Naks = %+v, want one Nak", res.Obs.Naks)
			}
		})
	}
}
