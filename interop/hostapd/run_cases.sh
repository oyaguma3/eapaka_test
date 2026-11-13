#!/bin/sh
# run.sh で起動した hostapd に対して、testdata/interop/hostapd のケースを順に実行する。
# 引数でケースを指定することもできる。1 件でも PASS しなければ終了コードは 1。
set -u

DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$DIR/../.." && pwd)
BIN=$DIR/_build/eapaka_test

(cd "$ROOT" && go build -o "$BIN" ./cmd/eapaka_test) || exit 2

if [ "$#" -eq 0 ]; then
	set -- "$ROOT"/testdata/interop/hostapd/*.yaml
fi
failed=0
for c in "$@"; do
	name=$(basename "$c" .yaml)
	log=$DIR/_build/$name.log
	if "$BIN" -c "$ROOT/configs/hostapd.yaml" run "$c" >"$log" 2>&1; then
		echo "PASS $name"
	else
		echo "FAIL $name (exit $?; see $log)"
		failed=1
	fi
done
exit "$failed"
