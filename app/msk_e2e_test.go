package app

import (
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
