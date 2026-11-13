package app

import (
	"encoding/json/v2"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/oyaguma3/eapaka_test/conformance"
)

// WriteReport は実行結果を format（json / junit）で書き出す（X7）。
// 鍵や識別子は含めない。
func WriteReport(w io.Writer, format string, runs []CaseRun) error {
	switch format {
	case "json":
		return writeJSONReport(w, runs)
	case "junit":
		return writeJUnitReport(w, runs)
	default:
		return fmt.Errorf("unsupported report format %q (use json or junit)", format)
	}
}

type jsonViolation struct {
	ID     string `json:"id"`
	Level  string `json:"level"`
	Action string `json:"action"`
	Ref    string `json:"ref"`
	Round  int    `json:"round"`
	Detail string `json:"detail"`
}

type jsonCase struct {
	Name       string          `json:"name"`
	File       string          `json:"file"`
	Iteration  int             `json:"iteration"`
	Result     string          `json:"result"`
	ExitCode   int             `json:"exit_code"`
	Error      string          `json:"error,omitempty"`
	DurationMS int64           `json:"duration_ms"`
	AuthType   string          `json:"auth_type,omitempty"`
	MSKMatch   *bool           `json:"msk_match,omitempty"`
	Violations []jsonViolation `json:"violations"`
}

type jsonReport struct {
	Summary struct {
		Total    int `json:"total"`
		Pass     int `json:"pass"`
		Fail     int `json:"fail"`
		Error    int `json:"error"`
		ExitCode int `json:"exit_code"`
	} `json:"summary"`
	Cases []jsonCase `json:"cases"`
}

func toJSONViolations(vs []conformance.Violation) []jsonViolation {
	out := make([]jsonViolation, 0, len(vs))
	for _, v := range vs {
		out = append(out, jsonViolation{ID: v.Rule.ID, Level: string(v.Rule.Level), Action: string(v.Action), Ref: v.Rule.Ref, Round: v.Round, Detail: v.Detail})
	}
	return out
}

func writeJSONReport(w io.Writer, runs []CaseRun) error {
	var rep jsonReport
	rep.Cases = make([]jsonCase, 0, len(runs))
	for _, r := range runs {
		c := jsonCase{
			Name: r.Name, File: r.File, Iteration: r.Iteration, Result: r.Outcome(), ExitCode: r.Result.ExitCode,
			DurationMS: r.Duration.Milliseconds(), AuthType: r.Result.Obs.AuthType, MSKMatch: r.Result.Obs.MSKMatch,
			Violations: toJSONViolations(r.Result.Violations),
		}
		if r.Result.Err != nil {
			c.Error = r.Result.Err.Error()
		}
		rep.Cases = append(rep.Cases, c)
		switch c.Result {
		case "pass":
			rep.Summary.Pass++
		case "fail":
			rep.Summary.Fail++
		default:
			rep.Summary.Error++
		}
	}
	rep.Summary.Total = len(runs)
	rep.Summary.ExitCode = MaxExitCode(runs)
	b, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", b)
	return err
}

// JUnit XML（CI で読める形）。FAIL は failure、ERROR は error にする。
type junitSuites struct {
	XMLName xml.Name     `xml:"testsuites"`
	Suites  []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Errors   int         `xml:"errors,attr"`
	Time     string      `xml:"time,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitMessage `xml:"failure,omitempty"`
	Error     *junitMessage `xml:"error,omitempty"`
	SystemOut string        `xml:"system-out,omitempty"`
}

type junitMessage struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

func seconds(d time.Duration) string { return fmt.Sprintf("%.3f", d.Seconds()) }

func writeJUnitReport(w io.Writer, runs []CaseRun) error {
	suite := junitSuite{Name: "eapaka_test", Tests: len(runs)}
	var total time.Duration
	for _, r := range runs {
		total += r.Duration
		c := junitCase{Name: r.Name, ClassName: "eapaka_test." + strings.TrimSuffix(r.File, ".yaml"), Time: seconds(r.Duration)}
		var lines []string
		for _, v := range r.Result.Violations {
			lines = append(lines, fmt.Sprintf("violation id=%s level=%s action=%s ref=%q round=%d detail=%q",
				v.Rule.ID, v.Rule.Level, v.Action, v.Rule.Ref, v.Round, v.Detail))
		}
		c.SystemOut = strings.Join(lines, "\n")
		msg := ""
		if r.Result.Err != nil {
			msg = r.Result.Err.Error()
		}
		switch r.Outcome() {
		case "fail":
			suite.Failures++
			c.Failure = &junitMessage{Message: msg, Type: "fail", Body: c.SystemOut}
		case "error":
			suite.Errors++
			c.Error = &junitMessage{Message: msg, Type: "error"}
		}
		suite.Cases = append(suite.Cases, c)
	}
	suite.Time = seconds(total)
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(junitSuites{Suites: []junitSuite{suite}}); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}
