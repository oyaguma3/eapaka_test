package app

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/oyaguma3/eapaka_test/config"
	"github.com/oyaguma3/eapaka_test/idstore"
	"github.com/oyaguma3/eapaka_test/internal/fakeserver"
	"github.com/oyaguma3/eapaka_test/testcase"

	eapaka "github.com/oyaguma3/go-eapaka"
)

// fileIDStore は、識別子ストアを一時ディレクトリのファイルに置いた設定を返す。
func fileIDStore(t *testing.T, cfg config.Config) config.Config {
	t.Helper()
	cfg.IdentityStore = config.IdentityStoreConfig{Mode: "file", Path: filepath.Join(t.TempDir(), "ids.json")}
	return cfg
}

// TestE2EPseudonymIssueAndUse は、受け取った仮名を保存し、次の実行で使えることを確かめる。
func TestE2EPseudonymIssueAndUse(t *testing.T) {
	for _, m := range []struct {
		name, method, pseudonym string
		eapType                 uint8
	}{
		{"aka", "aka", "2pseudo123", eapaka.TypeAKA},
		{"aka_prime", "aka_prime", "7pseudo123", eapaka.TypeAKAPrime},
	} {
		t.Run(m.name, func(t *testing.T) {
			srv := startServer(t, fakeserver.Config{Method: m.eapType, IssuePseudonym: m.pseudonym, KnownPseudonyms: []string{m.pseudonym}})
			cfg := fileIDStore(t, e2eConfig(srv))

			issue := e2eCase(t, "", "accept")
			issue.IdentitySource, issue.Method = "permanent", m.method
			issue.Expect.NextPseudonym = "present"
			issue.Expect.MPPE.VerifyMSK = true
			if res := Run(t.Context(), cfg, issue); res.ExitCode != 0 {
				t.Fatalf("issue: exit = %d, err = %v", res.ExitCode, res.Err)
			}
			e, err := (&idstore.FileStore{Path: cfg.IdentityStore.Path}).Get(cfg.SIM.IMSI, idstore.MethodFor(m.eapType))
			if err != nil || e.Pseudonym == nil || e.Pseudonym.Username != m.pseudonym {
				t.Fatalf("stored entry = %+v, %v", e, err)
			}

			use := e2eCase(t, "", "accept")
			use.IdentitySource, use.Method = "pseudonym", m.method
			use.Expect.IdentityRequests = []string{}
			use.Expect.MPPE.VerifyMSK = true
			if res := Run(t.Context(), cfg, use); res.ExitCode != 0 {
				t.Fatalf("use: exit = %d, err = %v", res.ExitCode, res.Err)
			}
		})
	}
}

// TestE2EPseudonymRules は、仮名・AT_ENCR_DATA・AKA-Identity・AT_CHECKCODE に関するピアの動作と規則を確かめる。
func TestE2EPseudonymRules(t *testing.T) {
	tests := []struct {
		name      string
		cfg       fakeserver.Config
		identity  string
		expect    string
		check     func(*testcase.Expect)
		wantRules []string
		wantExit  int
	}{
		{
			name: "unknown pseudonym gets a permanent identity request", cfg: fakeserver.Config{},
			identity: "2unknown", expect: "accept",
			check: func(e *testcase.Expect) { e.IdentityRequests = []string{"permanent"} },
		},
		{
			name: "AT_CHECKCODE after an identity round", cfg: fakeserver.Config{IdentityRequest: "any", Checkcode: true},
			expect: "accept",
			check:  func(e *testcase.Expect) { e.Checkcode = "verified"; e.IdentityRequests = []string{"any"} },
		},
		{
			name: "AT_CHECKCODE without an identity round", cfg: fakeserver.Config{Method: eapaka.TypeAKAPrime, Checkcode: true},
			expect: "accept",
			check:  func(e *testcase.Expect) { e.Checkcode = "verified" },
		},
		{
			name: "A-01 AT_ANY_ID_REQ twice", cfg: fakeserver.Config{IdentityRequest: "any", Faults: fakeserver.Faults{AnyIDTwice: true}},
			expect: "accept", wantRules: []string{"A-01"}, wantExit: 1,
		},
		{
			name: "A-05 non-zero padding", cfg: fakeserver.Config{IssuePseudonym: "2abcd", Faults: fakeserver.Faults{NonZeroPadding: true}},
			expect: "reject", wantRules: []string{"A-05"}, wantExit: 1,
		},
		{
			name: "A-06 pseudonym with a realm", cfg: fakeserver.Config{IssuePseudonym: "2abc@example.org"},
			expect: "accept", wantRules: []string{"A-06"}, wantExit: 1,
		},
		{
			name: "A-06 unencrypted AT_NEXT_PSEUDONYM", cfg: fakeserver.Config{IssuePseudonym: "2abcdefg", Faults: fakeserver.Faults{PlainNextPseudonym: true}},
			expect: "accept", wantRules: []string{"A-06"}, wantExit: 1,
		},
		{
			name: "A-07 AT_RESULT_IND in AT_ENCR_DATA", cfg: fakeserver.Config{Faults: fakeserver.Faults{ResultIndInEncr: true}},
			expect: "accept", wantRules: []string{"A-07"}, wantExit: 1,
		},
		{
			name: "A-14 AKA' pseudonym revealing the IMSI (warn)", cfg: fakeserver.Config{Method: eapaka.TypeAKAPrime, IssuePseudonym: "7440100123456789x"},
			expect: "accept", wantRules: []string{"A-14"}, wantExit: 0,
		},
		{
			name: "A-19 wrong AT_CHECKCODE", cfg: fakeserver.Config{IdentityRequest: "any", Checkcode: true, Faults: fakeserver.Faults{WrongCheckcode: true}},
			expect: "reject", wantRules: []string{"A-19"}, wantExit: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startServer(t, tt.cfg)
			prefix := "0"
			if tt.cfg.Method == eapaka.TypeAKAPrime {
				prefix = "6"
			}
			identity := prefix + "440100123456789"
			if tt.identity != "" {
				identity = tt.identity
			}
			tc := e2eCase(t, identity+"@"+e2eRealm, tt.expect)
			if tt.check != nil {
				tt.check(&tc.Expect)
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
			if res.ExitCode != tt.wantExit {
				t.Errorf("exit = %d, want %d (err=%v)", res.ExitCode, tt.wantExit, res.Err)
			}
		})
	}
}

// TestE2EIVReuseAcrossRuns は、実行をまたいだ AT_IV の再利用を A-02 で検出することを確かめる。
func TestE2EIVReuseAcrossRuns(t *testing.T) {
	srv := startServer(t, fakeserver.Config{IssuePseudonym: "2abcdefg", Faults: fakeserver.Faults{FixedIV: true}})
	cfg := fileIDStore(t, e2eConfig(srv))
	first := Run(t.Context(), cfg, e2eCase(t, "0440100123456789@"+e2eRealm, "accept"))
	if first.ExitCode != 0 {
		t.Fatalf("first run: exit = %d, err = %v", first.ExitCode, first.Err)
	}
	second := Run(t.Context(), cfg, e2eCase(t, "0440100123456789@"+e2eRealm, "accept"))
	if !slices.Contains(violationIDs(second.Violations), "A-02") || second.ExitCode != 1 {
		t.Errorf("second run: violations = %v, exit = %d", violationIDs(second.Violations), second.ExitCode)
	}
}
