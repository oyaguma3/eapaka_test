#!/bin/sh
# run.sh で起動した hostapd に対して、testdata/interop/hostapd のケースを 1 回の実行で流す。
# 引数でケースやディレクトリを指定することもできる。
#
# 結果: _build/report.xml（JUnit）、_build/trace.log（トレース）。終了コードは全ケースの最大値。
set -u

DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$DIR/../.." && pwd)
BUILD=$DIR/_build
BIN=$BUILD/eapaka_test

mkdir -p "$BUILD"
(cd "$ROOT" && go build -o "$BIN" ./cmd/eapaka_test) || exit 2

if [ "$#" -eq 0 ]; then
	set -- "$ROOT/testdata/interop/hostapd"
fi
"$BIN" -c "$ROOT/configs/hostapd.yaml" --report junit --report-file "$BUILD/report.xml" run "$@" 2> "$BUILD/trace.log"
code=$?
grep -E '^(PASS|FAIL|ERROR) ' "$BUILD/trace.log"
echo "exit $code (report: $BUILD/report.xml, trace: $BUILD/trace.log)"
exit "$code"
