#!/bin/bash
# テスト対象サーバ（aka-radius＋aka-vecgen）を、aka-mvpset の verify/stage2 の構成で
# WSL2 の中に立て、eapaka_test のケースを流す。
#
#   ./ctl.sh images         aka-radius・aka-vecgen・エッジの代わりのイメージを手元のクローンからビルドする
#   ./ctl.sh setup          作業場所を作り、stage2.sh の準備部分で起動と初期登録を行う（初回だけ）
#   ./ctl.sh up             止めておいた構成を起動する（登録は Valkey のボリュームに残っている）
#   ./ctl.sh down [-v]      止める。-v を付けるとボリュームも消す（登録も消える）
#   ./ctl.sh run [ケース…]  ケースを流す（既定は testdata/interop/aka-radius の全ケース）
#   ./ctl.sh status         コンテナの状態と、証明書の期限を表示する
#
# 場所は環境変数で変えられる: AKA_WORK（作業場所。既定 ~/aka-work/stage2）、
# MVPSET_DIR・RADIUS_DIR・VECGEN_DIR（各リポジトリのクローン。既定 ~/projects/ の下）
set -euo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$DIR/../.." && pwd)
W=${AKA_WORK:-$HOME/aka-work/stage2}
MVPSET_DIR=${MVPSET_DIR:-$HOME/projects/aka-mvpset}
RADIUS_DIR=${RADIUS_DIR:-$HOME/projects/aka-radius}
VECGEN_DIR=${VECGEN_DIR:-$HOME/projects/aka-vecgen}
STAGE2=$MVPSET_DIR/verify/stage2
BUILD=$DIR/_build

# stage2.sh と同じ呼び出し（プロジェクト名 s2vecgen・s2radius）
vc() { (cd "$W/vecgen" && docker compose -p s2vecgen -f compose.yaml -f compose.fluent-bit.yaml -f "$W/tools/compose.vecgen.yaml" "$@"); }
rc() { (cd "$W/radius/deployments" && docker compose -p s2radius -f docker-compose.yml -f docker-compose.aka-av.yml -f "$W/tools/compose.radius.yaml" "$@"); }

die() {
	echo "ctl.sh: $*" >&2
	exit 1
}

cmd_images() {
	docker build -t aka-radius:dev --build-arg VERSION="$(git -C "$RADIUS_DIR" rev-parse --short HEAD)" "$RADIUS_DIR"
	docker build -t aka-vecgen:stage2 --build-arg VERSION="$(git -C "$VECGEN_DIR" rev-parse --short HEAD)" "$VECGEN_DIR"
	docker build -t stage2-tools:dev "$STAGE2"
}

cmd_setup() {
	if docker volume inspect s2radius_valkey_data s2vecgen_valkey-data > /dev/null 2>&1; then
		die "s2radius / s2vecgen volumes already exist; use 'up', or 'down -v' before setting up again"
	fi
	for img in aka-radius:dev aka-vecgen:stage2 stage2-tools:dev; do
		docker image inspect "$img" > /dev/null 2>&1 || die "image $img is missing; run './ctl.sh images' first"
	done
	# 作業場所の配置（aka-mvpset/verify/stage2/README.md の「配置」）
	mkdir -p "$W/vecgen" "$W/radius" "$W/tools"
	cp "$VECGEN_DIR"/{compose.yaml,compose.fluent-bit.yaml,.env.example} "$W/vecgen/"
	cp -r "$RADIUS_DIR"/{deployments,configs,scripts} "$W/radius/"
	cp "$STAGE2"/{compose.radius.yaml,compose.vecgen.yaml,edge-t42.conf,edge-t7.conf} "$W/tools/"
	# stage2.sh の準備部分（EAP の試験の手前まで）だけを使う
	awk '/^# -+ EAP/ { exit } { print }' "$STAGE2/stage2.sh" > "$W/tools/prep.sh"
	chmod +x "$W/tools/prep.sh"
	"$W/tools/prep.sh"
}

cmd_up() {
	[ -d "$W/tools" ] || die "$W is not set up; run './ctl.sh setup' first"
	# 共有ネットワーク aka-av は aka-vecgen 側が作るので、先に起動する
	vc up -d --wait --wait-timeout 120
	rc up -d --wait --wait-timeout 120
}

cmd_down() {
	[ -d "$W/tools" ] || die "$W is not set up"
	rc down "$@"
	vc down "$@"
}

cmd_status() {
	docker ps -a --filter name=s2radius --filter name=s2vecgen --format '{{.Names}}\t{{.Status}}'
	# stage2.sh が作るクライアント証明書は 30 日で切れる
	for c in "$W/radius/deployments/sources/vecgen-client.pem" "$W/pki/prov.pem"; do
		[ -f "$c" ] && echo "$(basename "$c") $(openssl x509 -enddate -noout -in "$c")"
	done
}

cmd_run() {
	mkdir -p "$BUILD"
	(cd "$ROOT" && CGO_ENABLED=0 go build -o "$BUILD/eapaka_test" ./cmd/eapaka_test)
	if [ "$#" -eq 0 ]; then
		set -- "$ROOT"/testdata/interop/aka-radius/{aka,aka_prime}/*.yaml
	fi
	local failed=0 c method name log
	for c in "$@"; do
		# ケースのディレクトリ名（aka / aka_prime）で設定を選ぶ
		method=$(basename "$(dirname "$c")")
		name=$method-$(basename "$c" .yaml)
		log=$BUILD/$name.log
		if "$BUILD/eapaka_test" -c "$ROOT/configs/aka-radius-${method//_/-}.yaml" run "$c" > "$log" 2>&1; then
			echo "PASS $name"
		else
			echo "FAIL $name (exit $?; $(grep -m1 '^conformance' "$log" || true); see $log)"
			failed=1
		fi
	done
	return "$failed"
}

case "${1:-}" in
images | setup | up | down | run | status)
	c=$1
	shift
	"cmd_$c" "$@"
	;;
*)
	sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
	exit 2
	;;
esac
