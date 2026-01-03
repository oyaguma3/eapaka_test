package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/oyaguma3/eapaka_test/app"
	"github.com/oyaguma3/eapaka_test/config"
	"github.com/oyaguma3/eapaka_test/testcase"
)

func main() {
	var cfgPath string
	var unsafeLog bool
	var dumpEAPHex bool
	var dumpRadiusAttrs bool
	flag.StringVar(&cfgPath, "c", "", "config file path")
	flag.BoolVar(&unsafeLog, "unsafe-log", false, "output sensitive EAP data in trace")
	flag.BoolVar(&dumpEAPHex, "trace-eap-hex", false, "dump EAP hex in verbose trace")
	flag.BoolVar(&dumpRadiusAttrs, "trace-radius-attrs", false, "dump RADIUS attrs in verbose trace")
	flag.Parse()

	args := flag.Args()
	if len(args) < 2 || args[0] != "run" {
		usage()
		os.Exit(2)
	}
	if cfgPath == "" {
		fmt.Fprintln(os.Stderr, "config path is required")
		usage()
		os.Exit(2)
	}
	casePath := args[1]

	cfg, err := config.LoadFile(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	caseData, err := testcase.LoadFile(casePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if unsafeLog {
		caseData.Trace.UnsafeLog = true
	}
	if dumpEAPHex {
		value := true
		caseData.Trace.DumpEAPHex = &value
	}
	if dumpRadiusAttrs {
		value := true
		caseData.Trace.DumpRadiusAttrs = &value
	}

	exitCode, err := app.RunCase(context.Background(), cfg, caseData)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		if exitCode == 0 {
			exitCode = 2
		}
	}
	os.Exit(exitCode)
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: eapaka_test -c <config> run <testcase>")
	flag.PrintDefaults()
}
