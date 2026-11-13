package app

import (
	"bytes"
	"encoding/json/v2"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/oyaguma3/eapaka_test/internal/fakeserver"

	eapaka "github.com/oyaguma3/go-eapaka"
)

// TestRunAllSharedMemoryStore は、同じ Runner の中で memory モードのストアを共有し、
// 鍵をディスクに書かずに「フル認証 → 再認証の繰り返し」ができることを確かめる（X7）。
func TestRunAllSharedMemoryStore(t *testing.T) {
	srv := startServer(t, fakeserver.Config{Method: eapaka.TypeAKAPrime, IssueReauthID: "8re"})
	cfg := e2eConfig(srv) // identity_store も sqn_store も memory

	full := e2eCase(t, "", "accept")
	full.Name, full.IdentitySource, full.Method = "full", "permanent", "aka_prime"
	reauth := e2eCase(t, "", "accept")
	reauth.Name, reauth.IdentitySource, reauth.Method, reauth.Repeat = "reauth", "reauth", "aka_prime", 3
	reauth.Expect.AuthType = "reauth"
	reauth.Expect.MPPE.VerifyMSK = true

	runs := NewRunner(cfg).RunAll(t.Context(), []LoadedCase{{File: "full.yaml", Case: full}, {File: "reauth.yaml", Case: reauth}}, false, nil)
	if len(runs) != 4 || MaxExitCode(runs) != 0 {
		t.Fatalf("runs = %d, max exit = %d", len(runs), MaxExitCode(runs))
	}
	for i, r := range runs[1:] {
		if r.Result.Obs.ReauthCounter != uint16(i+1) || r.Name != "reauth#"+string(rune('1'+i)) {
			t.Errorf("run %s: counter = %d", r.Name, r.Result.Obs.ReauthCounter)
		}
		if len(r.Result.Obs.SessionID) != 1+16+16 || r.Result.Obs.SessionID[0] != 0x32 {
			t.Errorf("run %s: Session-Id = %x", r.Name, r.Result.Obs.SessionID)
		}
	}
	if sid := runs[0].Result.Obs.SessionID; len(sid) != 33 || sid[0] != 0x32 {
		t.Errorf("full authentication Session-Id = %x", sid)
	}
}

// TestRunAllStopOnFailAndReports は、--stop-on-fail と JSON / JUnit のレポートを確かめる。
func TestRunAllStopOnFailAndReports(t *testing.T) {
	srv := startServer(t, fakeserver.Config{Faults: fakeserver.Faults{OmitMessageAuthenticator: true}})
	cfg := e2eConfig(srv)
	pass := e2eCase(t, "0440100123456789@"+e2eRealm, "accept")
	pass.Name = "warn_only" // R-02 は warn なので PASS
	fail := e2eCase(t, "0440100123456789@"+e2eRealm, "reject")
	fail.Name = "wrong_expectation"
	never := e2eCase(t, "0440100123456789@"+e2eRealm, "accept")
	never.Name = "not_run"
	cases := []LoadedCase{{File: "a.yaml", Case: pass}, {File: "b.yaml", Case: fail}, {File: "c.yaml", Case: never}}

	runs := NewRunner(cfg).RunAll(t.Context(), cases, true, nil)
	if len(runs) != 2 || MaxExitCode(runs) != 1 {
		t.Fatalf("runs = %d, max exit = %d; want 2 runs stopping at the failure", len(runs), MaxExitCode(runs))
	}

	var js bytes.Buffer
	if err := WriteReport(&js, "json", runs); err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Summary struct{ Total, Pass, Fail, Error, ExitCode int } `json:"summary"`
		Cases   []struct {
			Name       string `json:"name"`
			Result     string `json:"result"`
			Violations []struct {
				ID string `json:"id"`
			} `json:"violations"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(js.Bytes(), &rep, json.MatchCaseInsensitiveNames(true)); err != nil {
		t.Fatalf("JSON report: %v\n%s", err, js.String())
	}
	if rep.Summary.Total != 2 || rep.Summary.Pass != 1 || rep.Summary.Fail != 1 || rep.Cases[0].Violations[0].ID != "R-02" {
		t.Errorf("JSON report = %+v", rep)
	}

	var ju bytes.Buffer
	if err := WriteReport(&ju, "junit", runs); err != nil {
		t.Fatal(err)
	}
	var suites struct {
		Suites []struct {
			Tests    int `xml:"tests,attr"`
			Failures int `xml:"failures,attr"`
			Cases    []struct {
				Name    string `xml:"name,attr"`
				Failure *struct {
					Message string `xml:"message,attr"`
				} `xml:"failure"`
			} `xml:"testcase"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal(ju.Bytes(), &suites); err != nil {
		t.Fatalf("JUnit report: %v\n%s", err, ju.String())
	}
	s := suites.Suites[0]
	if s.Tests != 2 || s.Failures != 1 || s.Cases[1].Failure == nil || !strings.Contains(s.Cases[1].Failure.Message, "expect result") {
		t.Errorf("JUnit report = %+v\n%s", s, ju.String())
	}
}
