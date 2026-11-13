package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/oyaguma3/eapaka_test/app"
	"github.com/oyaguma3/eapaka_test/config"
	"github.com/oyaguma3/eapaka_test/testcase"
)

func main() {
	os.Exit(run())
}

func run() int {
	var cfgPath, report, reportFile string
	var unsafeLog, dumpEAPHex, dumpRadiusAttrs, stopOnFail bool
	flag.StringVar(&cfgPath, "c", "", "config file path")
	flag.BoolVar(&unsafeLog, "unsafe-log", false, "output sensitive EAP data in trace")
	flag.BoolVar(&dumpEAPHex, "trace-eap-hex", false, "dump EAP hex in verbose trace")
	flag.BoolVar(&dumpRadiusAttrs, "trace-radius-attrs", false, "dump RADIUS attrs in verbose trace")
	flag.StringVar(&report, "report", "", "write a report of all cases: json or junit")
	flag.StringVar(&reportFile, "report-file", "", "report output file (default: standard output)")
	flag.BoolVar(&stopOnFail, "stop-on-fail", false, "stop at the first case that does not pass")
	flag.Parse()

	args := flag.Args()
	if len(args) < 2 || args[0] != "run" {
		usage()
		return 2
	}
	if cfgPath == "" {
		fmt.Fprintln(os.Stderr, "config path is required")
		usage()
		return 2
	}
	if report != "" && report != "json" && report != "junit" {
		fmt.Fprintln(os.Stderr, "--report must be json or junit")
		return 2
	}

	cfg, err := config.LoadFile(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	files, err := expandCasePaths(args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	var cases []app.LoadedCase
	for _, f := range files {
		tc, err := testcase.LoadFile(f)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if unsafeLog {
			tc.Trace.UnsafeLog = true
		}
		if dumpEAPHex {
			tc.Trace.DumpEAPHex = new(true)
		}
		if dumpRadiusAttrs {
			tc.Trace.DumpRadiusAttrs = new(true)
		}
		cases = append(cases, app.LoadedCase{File: f, Case: tc})
	}

	// ケースが 1 つなら、従来どおり結果の行は出さず、エラーだけを出す
	single := len(cases) == 1 && max(cases[0].Case.Repeat, 1) == 1
	runs := app.NewRunner(cfg).RunAll(context.Background(), cases, stopOnFail, func(r app.CaseRun) {
		if r.Result.Err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", r.Name, r.Result.Err)
		}
		if !single {
			fmt.Fprintf(os.Stderr, "%s %s (exit %d)\n", map[string]string{"pass": "PASS", "fail": "FAIL", "error": "ERROR"}[r.Outcome()], r.Name, r.Result.ExitCode)
		}
	})

	if report != "" {
		var w io.Writer = os.Stdout
		if reportFile != "" {
			f, err := os.Create(reportFile)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 2
			}
			defer f.Close()
			w = f
		}
		if err := app.WriteReport(w, report, runs); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}
	return app.MaxExitCode(runs)
}

// expandCasePaths は、ケースのファイルとディレクトリを、実行するファイルの並びにする。
// ディレクトリの中の *.yaml / *.yml はファイル名の順に並べる（サブディレクトリは見ない）。
func expandCasePaths(paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			out = append(out, p)
			continue
		}
		var found []string
		for _, pattern := range []string{"*.yaml", "*.yml"} {
			m, err := filepath.Glob(filepath.Join(p, pattern))
			if err != nil {
				return nil, err
			}
			found = append(found, m...)
		}
		if len(found) == 0 {
			return nil, fmt.Errorf("no test cases (*.yaml) in %s", p)
		}
		slices.Sort(found)
		out = append(out, found...)
	}
	return out, nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: eapaka_test -c <config> [--report json|junit] [--report-file <path>] [--stop-on-fail] run <testcase|dir>...")
	flag.PrintDefaults()
}
