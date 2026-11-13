#!/bin/sh
# hlr_auc_gw と hostapd を起動する。Ctrl-C で両方を止める。
# HOSTAPD_DEBUG=1 で hostapd のデバッグ出力（-dd）を有効にする。
set -eu

DIR=$(cd "$(dirname "$0")" && pwd)
BUILD=$DIR/_build
RUN=$BUILD/run

if [ ! -x "$BUILD/hostapd" ] || [ ! -x "$BUILD/hlr_auc_gw" ]; then
	echo "run.sh: run build.sh first" >&2
	exit 1
fi
mkdir -p "$RUN"
rm -f "$RUN/hlr_auc_gw.sock"
sed -e "s|@RUN@|$RUN|g" -e "s|@DIR@|$DIR|g" "$DIR/hostapd.conf.in" > "$RUN/hostapd.conf"

"$BUILD/hlr_auc_gw" -s "$RUN/hlr_auc_gw.sock" -m "$DIR/milenage_db" &
HLR=$!
trap 'kill "$HLR" 2>/dev/null || true' EXIT INT TERM

debug=
if [ "${HOSTAPD_DEBUG:-}" = 1 ]; then
	debug=-dd
fi
"$BUILD/hostapd" $debug "$RUN/hostapd.conf"
