package app

import (
	"slices"
	"strings"
	"testing"

	"github.com/oyaguma3/eapaka_test/internal/fakeserver"

	eapaka "github.com/oyaguma3/go-eapaka"
)

// TestE2EVerifyMSK は X2（MS-MPPE 鍵を復号して MSK と比べる）を確かめる。
func TestE2EVerifyMSK(t *testing.T) {
	tests := []struct {
		name       string
		method     uint8
		faults     fakeserver.Faults
		mapping    string
		wantMatch  bool
		wantDetail string
		wantExit   int
	}{
		{name: "aka", method: eapaka.TypeAKA, wantMatch: true},
		{name: "aka_prime", method: eapaka.TypeAKAPrime, wantMatch: true},
		{name: "aka_prime after KDF negotiation", method: eapaka.TypeAKAPrime, wantMatch: true},
		{name: "wrong key", method: eapaka.TypeAKA, faults: fakeserver.Faults{MPPEWrongKey: true},
			wantDetail: "MS-MPPE-Recv-Key does not match", wantExit: 1},
		{name: "swapped keys", method: eapaka.TypeAKAPrime, faults: fakeserver.Faults{MPPESwapped: true},
			wantDetail: "check mppe.mapping", wantExit: 1},
		{name: "swapped keys with swapped mapping", method: eapaka.TypeAKAPrime, faults: fakeserver.Faults{MPPESwapped: true},
			mapping: "swapped", wantMatch: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scfg := fakeserver.Config{Method: tt.method, Faults: tt.faults}
			if strings.Contains(tt.name, "KDF negotiation") {
				scfg.KDFOffer = []uint16{2, 1}
			}
			srv := startServer(t, scfg)
			cfg := e2eConfig(srv)
			if tt.mapping != "" {
				cfg.MPPE.Mapping = tt.mapping
			}
			identity := "0440100123456789@" + e2eRealm
			if tt.method == eapaka.TypeAKAPrime {
				identity = "6440100123456789@" + e2eRealm
			}
			tc := e2eCase(t, identity, "accept")
			tc.Expect.MPPE.VerifyMSK = true
			res := Run(t.Context(), cfg, tc)

			if res.Obs.MSKMatch == nil || *res.Obs.MSKMatch != tt.wantMatch {
				t.Fatalf("MSKMatch = %v, want %t (detail %q)", res.Obs.MSKMatch, tt.wantMatch, res.Obs.MSKDetail)
			}
			if !strings.Contains(res.Obs.MSKDetail, tt.wantDetail) {
				t.Errorf("MSKDetail = %q, want %q", res.Obs.MSKDetail, tt.wantDetail)
			}
			if res.ExitCode != tt.wantExit {
				t.Errorf("exit = %d, want %d (err=%v)", res.ExitCode, tt.wantExit, res.Err)
			}
		})
	}
}

// TestE2EVerifyMSKWithoutMSK は、MSK を導出する前の Access-Accept では照合が失敗することを確かめる。
func TestE2EVerifyMSKWithoutMSK(t *testing.T) {
	srv := startServer(t, fakeserver.Config{Faults: fakeserver.Faults{EarlyAccept: true}})
	tc := e2eCase(t, "0440100123456789@"+e2eRealm, "accept")
	tc.Expect.MPPE.VerifyMSK = true
	tc.Expect.MPPE.RequirePresent = new(false)
	tc.Conformance.Rules = map[string]string{"R-05": "off"}
	res := Run(t.Context(), e2eConfig(srv), tc)
	if res.Obs.MSKMatch != nil || res.ExitCode != 1 || !strings.Contains(res.Err.Error(), "not derived an MSK") {
		t.Errorf("MSKMatch = %v, exit = %d, err = %v", res.Obs.MSKMatch, res.ExitCode, res.Err)
	}
}

// TestE2EKeyName は、Access-Accept の EAP-Key-Name と Session-Id の照合（R-09・R-10、RFC 7268 §2.2）を確かめる。
func TestE2EKeyName(t *testing.T) {
	tests := []struct {
		name      string
		method    uint8
		faults    fakeserver.Faults
		request   bool
		wantKey   string
		wantRules []string
		wantExit  int
	}{
		{name: "aka match", method: eapaka.TypeAKA, request: true, wantKey: "match"},
		{name: "aka_prime match", method: eapaka.TypeAKAPrime, request: true, wantKey: "match"},
		{name: "R-10 not requested", method: eapaka.TypeAKA, wantKey: "match", wantRules: []string{"R-10"}},
		{name: "R-09 mismatch", method: eapaka.TypeAKAPrime, request: true, faults: fakeserver.Faults{WrongKeyName: true},
			wantKey: "mismatch", wantRules: []string{"R-09"}, wantExit: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startServer(t, fakeserver.Config{Method: tt.method, KeyName: true, Faults: tt.faults})
			cfg := e2eConfig(srv)
			cfg.RadiusAttrs.EAPKeyName = tt.request
			identity := "0440100123456789@" + e2eRealm
			if tt.method == eapaka.TypeAKAPrime {
				identity = "6440100123456789@" + e2eRealm
			}
			res := Run(t.Context(), cfg, e2eCase(t, identity, "accept"))
			if res.Obs.KeyName != tt.wantKey {
				t.Errorf("KeyName = %q, want %q", res.Obs.KeyName, tt.wantKey)
			}
			if ids := violationIDs(res.Violations); !slices.Equal(ids, tt.wantRules) {
				t.Errorf("violations = %v, want %v", ids, tt.wantRules)
			}
			if res.ExitCode != tt.wantExit {
				t.Errorf("exit = %d, want %d (err=%v)", res.ExitCode, tt.wantExit, res.Err)
			}
		})
	}
}
