package app

import (
	"cmp"
	"context"
	"fmt"
	"time"

	"github.com/oyaguma3/eapaka_test/testcase"
)

// LoadedCase は、ファイルから読み込んだケース。
type LoadedCase struct {
	File string
	Case testcase.Case
}

// CaseRun は 1 回の実行の結果（repeat なら回ごと）。
type CaseRun struct {
	Name      string
	File      string
	Iteration int // repeat の何回目か（1 から数える）
	Result    Result
	Duration  time.Duration
}

// Outcome は結果の区分（pass / fail / error）を返す。
func (c CaseRun) Outcome() string {
	switch c.Result.ExitCode {
	case 0:
		return "pass"
	case 1:
		return "fail"
	default:
		return "error"
	}
}

// RunAll はケースを順に実行する（X7）。repeat の回数だけ続けて実行し、stopOnFail なら
// 最初に PASS しなかったところで止める。onDone は 1 回の実行が終わるたびに呼ぶ（nil 可）。
func (r *Runner) RunAll(ctx context.Context, cases []LoadedCase, stopOnFail bool, onDone func(CaseRun)) []CaseRun {
	var runs []CaseRun
	for _, lc := range cases {
		n := max(lc.Case.Repeat, 1)
		for i := range n {
			name := cmp.Or(lc.Case.Name, lc.File)
			if n > 1 {
				name = fmt.Sprintf("%s#%d", name, i+1)
			}
			start := time.Now()
			res := r.Run(ctx, lc.Case)
			run := CaseRun{Name: name, File: lc.File, Iteration: i + 1, Result: res, Duration: time.Since(start)}
			runs = append(runs, run)
			if onDone != nil {
				onDone(run)
			}
			if stopOnFail && res.ExitCode != 0 {
				return runs
			}
		}
	}
	return runs
}

// MaxExitCode は、全実行の終了コードの最大値を返す（ケースがなければ 0）。
func MaxExitCode(runs []CaseRun) int {
	code := 0
	for _, r := range runs {
		code = max(code, r.Result.ExitCode)
	}
	return code
}
