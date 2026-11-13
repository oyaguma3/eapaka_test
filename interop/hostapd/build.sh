#!/bin/sh
# hostap_2_12 を取得し、RADIUS サーバとして使う hostapd と hlr_auc_gw をビルドする。
# 暗号処理は hostap 内蔵の実装を使うので、OpenSSL や libnl は要らない。
#
# HOSTAP_URL で取得元を変えられる（例: 手元の hostap のクローン）。
set -eu

HOSTAP_TAG=hostap_2_12
HOSTAP_COMMIT=831364bf02710ad09c2f27d3efa92abeeb5634c0
HOSTAP_URL=${HOSTAP_URL:-https://w1.fi/hostap.git}

DIR=$(cd "$(dirname "$0")" && pwd)
BUILD=$DIR/_build
SRC=$BUILD/hostap

mkdir -p "$BUILD"
if [ ! -d "$SRC/.git" ]; then
	git -c advice.detachedHead=false clone --depth 1 --branch "$HOSTAP_TAG" "$HOSTAP_URL" "$SRC"
fi
actual=$(git -C "$SRC" rev-parse HEAD)
if [ "$actual" != "$HOSTAP_COMMIT" ]; then
	echo "build.sh: $SRC is at $actual, want $HOSTAP_COMMIT ($HOSTAP_TAG)" >&2
	exit 1
fi

# ビルド設定が変わったら作り直す
if ! cmp -s "$DIR/hostapd.build.config" "$SRC/hostapd/.config"; then
	make -C "$SRC/hostapd" clean >/dev/null
	cp "$DIR/hostapd.build.config" "$SRC/hostapd/.config"
fi
make -C "$SRC/hostapd" -j"$(nproc)" hostapd hlr_auc_gw
cp "$SRC/hostapd/hostapd" "$SRC/hostapd/hlr_auc_gw" "$BUILD/"
echo "build.sh: built $BUILD/hostapd and $BUILD/hlr_auc_gw ($HOSTAP_TAG)"
