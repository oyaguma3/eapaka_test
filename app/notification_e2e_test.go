package app

import (
	"slices"
	"strings"
	"testing"

	"github.com/oyaguma3/eapaka_test/conformance"
	"github.com/oyaguma3/eapaka_test/internal/fakeserver"
	"github.com/oyaguma3/eapaka_test/testcase"

	eapaka "github.com/oyaguma3/go-eapaka"
)

// TestE2ENotification は AKA-Notification と AT_RESULT_IND（RFC 4187 §6）、
// RFC 3748 の Notification と、関係する規則（A-08、A-10、R-05）を確かめる。
func TestE2ENotification(t *testing.T) {
	corruptMAC := []testcase.Fault{{At: "challenge_response", Action: "corrupt_mac"}}
	tests := []struct {
		name       string
		cfg        fakeserver.Config
		resultInd  *bool
		faults     []testcase.Fault
		expect     string
		notify     testcase.Notification
		wantRules  []string
		wantDetail string
	}{
		{
			name:   "success notification with AT_RESULT_IND",
			cfg:    fakeserver.Config{ResultInd: true},
			expect: "accept", notify: testcase.Notification{Code: new(eapaka.NotificationSuccess)},
		},
		{
			name: "peer does not use AT_RESULT_IND",
			cfg:  fakeserver.Config{Method: eapaka.TypeAKAPrime, ResultInd: true}, resultInd: new(false),
			expect: "accept", notify: testcase.Notification{Present: new(false)},
		},
		{
			name:   "failure before authentication",
			cfg:    fakeserver.Config{FailureNotification: true},
			faults: corruptMAC, expect: "reject",
			notify: testcase.Notification{Code: new(eapaka.NotificationGeneralFailure)},
		},
		{
			name:   "A-08 P and S both set",
			cfg:    fakeserver.Config{FailureNotification: true, Faults: fakeserver.Faults{NotificationPAndS: true}},
			faults: corruptMAC, expect: "reject", wantRules: []string{"A-08"},
		},
		{
			name:   "A-08 success notification without AT_RESULT_IND",
			cfg:    fakeserver.Config{Faults: fakeserver.Faults{SuccessNotifyWithoutResultInd: true}},
			expect: "accept", wantRules: []string{"A-08"},
		},
		{
			name:   "A-08 two notifications",
			cfg:    fakeserver.Config{ResultInd: true, Faults: fakeserver.Faults{TwoNotifications: true}},
			expect: "accept", wantRules: []string{"A-08"},
		},
		{
			name:   "R-05 Accept without the success notification",
			cfg:    fakeserver.Config{ResultInd: true, Faults: fakeserver.Faults{AcceptWithoutSuccessNotification: true}},
			expect: "accept", wantRules: []string{"R-05"}, wantDetail: "no success notification",
		},
		{
			name:   "R-05 Accept after a failure notification",
			cfg:    fakeserver.Config{FailureNotification: true, Faults: fakeserver.Faults{AcceptAfterFailureNotification: true}},
			faults: corruptMAC, expect: "reject", wantRules: []string{"R-05"}, wantDetail: "failure notification",
		},
		{
			name:   "A-10 Request after Client-Error",
			cfg:    fakeserver.Config{Faults: fakeserver.Faults{RequestAfterPeerError: true}},
			faults: []testcase.Fault{{At: "challenge_response", Action: "client_error"}}, expect: "reject",
			wantRules: []string{"A-10"},
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
			tc.EAP.ResultInd = tt.resultInd
			tc.Faults = tt.faults
			tc.Expect.Notification = tt.notify
			if tt.expect == "accept" {
				tc.Expect.MPPE.VerifyMSK = true
			}
			res := Run(t.Context(), e2eConfig(srv), tc)

			ids := violationIDs(res.Violations)
			for _, id := range tt.wantRules {
				if !slices.Contains(ids, id) {
					t.Errorf("violations = %v, want %s (err=%v)", ids, id, res.Err)
				}
			}
			if len(tt.wantRules) == 0 && len(ids) > 0 {
				t.Errorf("unexpected violations %v", ids)
			}
			if tt.wantDetail != "" && !slices.ContainsFunc(res.Violations, func(v conformance.Violation) bool {
				return strings.Contains(v.Detail, tt.wantDetail)
			}) {
				t.Errorf("no violation detail contains %q: %+v", tt.wantDetail, res.Violations)
			}
			wantExit := 0
			if len(tt.wantRules) > 0 {
				wantExit = 1
			}
			if res.ExitCode != wantExit {
				t.Errorf("exit = %d, want %d (err=%v)", res.ExitCode, wantExit, res.Err)
			}
		})
	}
}

// TestE2EEAPNotification は RFC 3748 の Notification（Type 2）に応答して認証を続けることを確かめる。
func TestE2EEAPNotification(t *testing.T) {
	srv := startServer(t, fakeserver.Config{EAPNotification: "maintenance tonight"})
	res := Run(t.Context(), e2eConfig(srv), e2eCase(t, "0440100123456789@"+e2eRealm, "accept"))
	if res.ExitCode != 0 || !slices.Equal(res.Obs.EAPNotifications, []string{"maintenance tonight"}) {
		t.Errorf("exit = %d, EAPNotifications = %q, err = %v", res.ExitCode, res.Obs.EAPNotifications, res.Err)
	}
}
