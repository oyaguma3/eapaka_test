# User Guide

[English](USER_GUIDE.md) | [日本語](USER_GUIDE_jp.md)

このドキュメントは外部利用者向けの使い方ガイドです。

## 1. 実行方法

```bash
./eapaka_test -c <config.yaml> run <case.yaml>
```

複数のケースやディレクトリを指定すると、1 回の実行で続けて流します。ディレクトリでは、中の `*.yaml` をファイル名の順に流します。

```bash
./eapaka_test -c <config.yaml> --report junit --report-file report.xml run <dir> <case.yaml>...
```

- memory モードの `sqn_store` と `identity_store` は、同じ実行のケースの間で共有します。そのため、鍵をディスクに書かずに「フル認証 → 再認証」の連鎖を試せます。
- 終了コードは全ケースの最大値です。ケースが複数のときは、ケースごとに `PASS` / `FAIL` / `ERROR` の行を標準エラーに出します。

## 2. CLI オプション

- `-c <path>`: 設定ファイル（必須）
- `run <case|dir>...`: テストケースファイルかディレクトリ（1 つ以上、必須）
- `--report json|junit`: 全ケースの結果（違反の一覧を含む）を出力する。junit は CI で読める JUnit XML
- `--report-file <path>`: レポートの出力先（既定: 標準出力）
- `--stop-on-fail`: 最初に PASS しなかったケースで止める
- `--unsafe-log`: 機密情報（RAND/AUTN/RES など）のマスクを解除して出力
- `--trace-eap-hex`: verbose で EAP hex dump を強制有効
- `--trace-radius-attrs`: verbose で RADIUS 属性一覧を強制有効

## 3. 設定ファイル（config）

例: `configs/example.yaml`

### 設定例

```yaml
radius:
  server_addr: "127.0.0.1:1812"
  secret: "testing123"
  timeout_ms: 1000
  retries: 3

radius_attrs:
  nas_ip_address: "192.0.2.10"
  nas_identifier: "eapaka_test"
  called_station_id: "aa-bb-cc-dd-ee-ff:MySSID"
  calling_station_id: "00-11-22-33-44-55"

eap:
  method_mismatch_policy: "warn"
  outer_identity_update_on_permanent_req: true
  permanent_id_policy: "always"
  aka_prime:
    net_name: "wlan.mnc010.mcc440.3gppnetwork.org"
    net_name_check: "off"
    empty_kdf_input: "reject"

identity:
  realm: "wlan.mnc010.mcc440.3gppnetwork.org"

sim:
  imsi: "440100123456789"
  ki: "00112233445566778899aabbccddeeff"
  opc: "00112233445566778899aabbccddeeff"
  amf: "8000"
  sqn_initial_hex: "000000000000"

sqn_store:
  mode: "file"
  path: "/tmp/eapaka_test-sqn.json"

conformance:
  default_must: "fail"
  default_should: "warn"
  rules: {}

mppe:
  mapping: "rfc5216"

identity_store:
  mode: "file"
  path: "/tmp/eapaka_test-identity.json"
```

主な項目:

- `radius.server_addr`: `<host>:<port>`
- `radius.secret`: RADIUS 共有秘密
- `radius.timeout_ms`: タイムアウト（ミリ秒）
- `radius.retries`: 再送回数

- `radius_attrs.*`: 追加 RADIUS 属性（任意）
  - `nas_ip_address`
  - `nas_identifier`
  - `called_station_id`（形式は後述）
  - `calling_station_id`

- `eap.*`: EAP ポリシー
  - `method_mismatch_policy`: `strict|warn|allow`
  - `outer_identity_update_on_permanent_req`: `true|false`
  - `permanent_id_policy`: `always|conservative|deny`
  - `aka_prime.net_name`: AKA' の Network Name。`net_name_check` での照合と、`empty_kdf_input: fallback` のときの補完に使う
  - `aka_prime.net_name_check`: `off|warn|reject`（既定: off）。AT_KDF_INPUT と `net_name` をコロン区切りのフィールドごとに比べる。不一致なら warn は警告だけ、reject は Authentication-Reject
  - `method_preference`: 使ってよい EAP メソッドの希望順（例: `[50, 23]`。既定は登録済みのすべてを AKA' → AKA の順）。外れたメソッドを提示されたら Nak で希望を返す
  - `nak`: 強制 Nak。`{ on: [50], propose: [23] }` なら、AKA' を提示されたときに AKA を希望する Nak を返す（サーバを AKA に誘導する bidding down の試験用）
  - `checkcode`: `auto|always|never`（既定: auto）。応答に AT_CHECKCODE を入れるか。auto はサーバが送ってきたときだけ入れる。サーバの AT_CHECKCODE は、AKA-Identity のやりとりと照合する
  - `result_ind`: `true|false`（既定: true）。サーバが AT_RESULT_IND を送ってきたときに、応答にも入れるか（RFC 4187 §6.2）。双方が使うと、成功通知を受けるまで EAP-Success を受け入れない
  - `bidding_policy`: `reject|ignore`（既定: reject）。EAP-AKA の Challenge の AT_BIDDING に D ビットが立っていたら、reject は Authentication-Reject を返す（RFC 9048 §4）。ignore は AKA にしか対応しないピアを模擬する
  - `aka_prime.empty_kdf_input`: `reject|fallback`（既定: reject）。AT_KDF_INPUT がない・空のときに Authentication-Reject を返すか、`net_name` で補って続けるか。どちらでも違反 A-13 として記録する

- `identity.realm`: Permanent ID 生成に使用する realm

- `sim.*`: USIM パラメータ
  - `imsi`
  - `ki`（16 bytes hex）
  - `opc`（16 bytes hex）
  - `amf`（2 bytes hex）。AUTN の AMF と違う場合は警告だけを出す
  - `sqn_initial_hex`（48 bit / 12 hex）

- `sqn_store.*`: SQN 永続化
  - `mode`: `file|memory`
  - `path`: file モード時に必須

- `conformance.*`: サーバ準拠性チェック（第 10 章）
  - `default_must`: MUST の規則の扱い `fail|warn|off`（既定: fail）
  - `default_should`: SHOULD の規則の扱い `fail|warn|off`（既定: warn）
  - `rules`: 規則 ID ごとの上書き（例: `{ R-02: off }`）

- `identity_store.*`: サーバから受け取った仮名と、AT_IV の履歴（再利用の検出用）を、IMSI とメソッドごとに保存する
  - `mode`: `memory|file`（既定: memory。実行をまたいで仮名を使うなら file）
  - `path`: file モード時に必須（パーミッション 0600 で保存）

- `mppe.mapping`: MS-MPPE 鍵と MSK の対応。`rfc5216`（既定。Recv-Key = MSK[0:32]、Send-Key = MSK[32:64]）か `swapped`

## 4. テストケース（case）

例: `testdata/cases/success_aka.yaml`

### テストケース例

```yaml
version: 1
name: success_aka
identity: "0440100123456789@wlan.mnc010.mcc440.3gppnetwork.org"
radius:
  attributes:
    called_station_id: "aa-bb-cc-dd-ee-ff:MySSID"
expect:
  result: accept
  mppe:
    require_present: true
```

主な項目:

- `identity`: 開始時の outer identity（`identity_source` が literal のときは必須）
- `identity_source`: 開始時の ID の選び方。`literal`（既定。`identity` をそのまま使う）、`permanent`（IMSI とレルムから永続 ID を作る）、`pseudonym`（保存済みの仮名＋レルム。なければ ERROR）、`reauth`（保存済みの再認証 ID。なければ ERROR）、`auto`（再認証 ID → 仮名 → 永続 ID）。再認証 ID は使う前にストアから外します（交換が完了しなくても再利用しない）
- `method`: `identity_source` が literal 以外のときの ID のメソッド。`aka|aka_prime`（既定: aka。永続 ID の先頭文字 0 / 6 と、使う仮名が決まる）
- `identity_store.reset`: 実行の前に、この IMSI の記録（仮名、再認証コンテキスト、AT_IV と NONCE_S の履歴）を消す
- `identity_store.persist`: 受け取った仮名を保存するか（既定: true。Access-Accept を受けたときに保存する）
- `radius.*`: config を上書きする RADIUS 設定（任意）
- `eap.*`: config を上書きする EAP 設定（任意）
  - `permanent_identity_override`: Permanent ID の完全指定
  - `aka_prime.net_name_check` / `aka_prime.empty_kdf_input` / `method_preference` / `nak` / `bidding_policy` / `result_ind`: config と同じ

- `sqn.reset`: SQN 初期化
- `sqn.persist`: 永続化を行うか（未指定は true）

- `expect.*`: 期待結果
  - `result`: `accept|reject`
  - `reject_hint_contains`: Reply-Message の部分一致
  - `reject_hint_check_presence`: `reject_hint_contains` 使用時に Reply-Message 必須とするか（既定: false）
  - `mppe.require_present`: MPPE 属性の存在確認
  - `mppe.send_key` / `mppe.recv_key`: `hex:` / `b64:` で固定値一致
  - `mppe.verify_msk`: MS-MPPE 鍵を復号し、ピアが導出した MSK と一致することを求める（第 6 章）
  - `next_pseudonym` / `next_reauth_id`: AT_ENCR_DATA で次回の仮名・再認証 ID を受け取るか（`present|absent`）
  - `identity_requests`: 受け取る AKA-Identity の要求の種類の並び（例: `[any, permanent]`。`[]` は AKA-Identity がないこと）
  - `checkcode`: AT_CHECKCODE の検証結果（`verified|absent`）
  - `auth_type`: 行われた認証の種類（`full|reauth`）
  - `counter_too_small_sent`: ピアが AT_COUNTER_TOO_SMALL を送ったか
  - `notification`: AKA-Notification の期待値。`code`（S・P ビットを含むコード値。32768 は成功、16384 は認証前の失敗）、`present`（受け取ったか）
  - `bidding`: AT_BIDDING の期待値。`present`（受け取ったか）、`d_bit`、`action`（ピアの動作 `reject|ignore`）。省略した項目は検査しない

- `repeat`: このケースを続けて実行する回数（既定 1）。再認証を繰り返して、AT_COUNTER が増え続けるかを確かめるのに使う。結果は `名前#1`、`名前#2` … として出る
- `trace.*`: トレース
  - `level`: `normal|verbose`
  - `unsafe_log`: 機密情報のマスク解除（CI では非推奨）
  - `dump_eap_hex`: EAP hex dump 出力（verbose 時のみ）
  - `dump_radius_attrs`: RADIUS 属性一覧出力（verbose 時のみ）
  - `save_path`: トレース出力先ファイル

- `conformance.rules`: このケースだけの規則の扱い（例: 開発中の既知の違反を一時的に `warn` にする）
- `fault`: ピアに注入する異常の一覧（第 10 章）

## 5. called_station_id の形式

`called_station_id` は以下の形式が推奨です。

- `xx-xx-xx-xx-xx-xx:MySSID`
  - MAC 部は 17 文字固定
  - `:` は 1 回のみ

verbose trace では形式不正時に警告が出ます。

## 6. MPPE の扱い

- Access-Accept には `MS-MPPE-Send-Key` / `MS-MPPE-Recv-Key` が必須
- 既定の運用は `require_present: true`（存在確認）
- 値一致検証は固定テストデータ運用時のみ使用
- `verify_msk: true` を指定すると、MS-MPPE 鍵を復号した値を、ピアが導出した MSK と比べます。対応付けは config の `mppe.mapping` で決めます。暗号化された値は Request Authenticator と Salt で毎回変わりますが、この方法は毎回の値に左右されずに確かめられます。トレースには一致したかどうかだけを出し、鍵の値は `--unsafe-log` でも出しません。
- hostapd を相手にした相互接続テストの手順は `interop/hostapd/README.md` にあります。
- テスト対象サーバ（aka-radius＋aka-vecgen）を WSL2 の中に立てて確かめる手順は `interop/aka-radius/README.md` にあります。

## 7. よくある使い方

```bash
./eapaka_test -c configs/example.yaml run testdata/cases/perm_id_req_from_pseudonym.yaml
./eapaka_test -c configs/example.yaml --unsafe-log run testdata/cases/success_aka.yaml
```

## 8. 注意点

- `--unsafe-log` / `trace.unsafe_log: true` は機密情報を出力するため、CI では非推奨です。
- `sqn_store.mode=file` では、同一の `path` を複数プロセスで同時使用しないでください。
- `method_mismatch_policy=strict` は EAP メソッドの不一致を FAIL とするため、テストケース側の指定に注意してください。

## 9. WSL 内での RADIUS パケットキャプチャ

WSL2（Ubuntu）内で eapaka_test と RADIUS サーバを動かす前提の場合、ループバック通信は Windows 側から見えないことが多いため、WSL 内でキャプチャする方法が確実です。

### 方法 A: WSL でキャプチャして Windows Wireshark で開く（推奨）

1) tcpdump をインストール

```bash
sudo apt update
sudo apt install -y tcpdump
```

2) WSL 内でキャプチャ開始（WSL 内同士の通信なら `lo` が最適）

```bash
sudo tcpdump -i lo -w /mnt/c/Users/<WindowsUser>/Desktop/radius.pcap 'udp port 1812 or 1813'
```

3) eapaka_test を実行し、通信させる  
4) Ctrl+C で停止し、Windows の Wireshark で `radius.pcap` を開く

### 方法 B: WSL の Wireshark GUI で直接キャプチャ

1) Wireshark をインストール

```bash
sudo apt update
sudo apt install -y wireshark
```

2) 権限付与（または `sudo wireshark` で起動）

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
sudo usermod -aG wireshark $USER
```

3) 再ログイン後、Wireshark を起動し `lo`（または `any`）でキャプチャ  
4) 表示フィルタに `udp.port == 1812 || udp.port == 1813` を指定

## 10. サーバ準拠性チェックと異常系の注入

### 準拠性チェック

認証結果が期待どおりでも、サーバの RFC 違反を検出して FAIL にできます。違反は規則ごとに記録します。各規則は `fail` / `warn` / `off` のどれかとして扱います（既定は MUST が fail、SHOULD が warn）。`fail` の違反が 1 件でもあると、期待結果と一致していても終了コードは 1 になります。

| ID | 検査内容 | 根拠 | レベル |
|---|---|---|---|
| R-01 | 応答の Message-Authenticator が正しい | RFC 3579 §3.2 | MUST |
| R-02 | EAP-Message を含む応答に Message-Authenticator がある | RFC 3579 §3.1 | SHOULD |
| R-03a | Access-Accept は EAP-Success を、Access-Reject は EAP-Failure を含む | RFC 3579 §2.6.3 | SHOULD |
| R-03b | Access-Challenge は EAP-Request を含む | RFC 3579 §2.1 | MUST |
| R-04 | EAP-Success/Failure の Identifier が直前の EAP-Response と一致する | RFC 3748 §4.2 | MUST |
| R-05 | メソッドの完了前や失敗後に成功を通知しない | RFC 3748 §4.2、RFC 4187 §6.2 | MUST |
| R-06 | メソッドの途中で EAP タイプを切り替えない | RFC 3748 §2.1 | MUST |
| R-07 | MS-MPPE 鍵の Salt の最上位ビットが 1 で、Send/Recv で重複しない | RFC 2548 §2.4.2 | MUST |
| A-01 | AKA-Identity は最大 3 回、AT_ANY_ID_REQ は 1 回目だけ、AT_PERMANENT_ID_REQ の後に Identity の要求をしない | RFC 4187 §4.1.5・§9.1 | MUST |
| A-02 | AT_IV を再利用しない（`identity_store` の履歴で、実行をまたいでも調べる） | RFC 4187 §10.12 | MUST |
| A-03 | AT_NONCE_S を再利用しない（`identity_store` の履歴で、実行をまたいでも調べる） | RFC 4187 §10.18 | MUST |
| A-04 | 再認証の AT_COUNTER が、それまでの再認証より大きい | RFC 4187 §5.1・§5.4 | MUST |
| A-05 | AT_ENCR_DATA が 16 バイトの倍数で、AT_PADDING がゼロ埋めで最後にある | RFC 4187 §10.12 | MUST |
| A-06 | AT_NEXT_PSEUDONYM にレルムを含めず、AT_NEXT_PSEUDONYM / AT_NEXT_REAUTH_ID は暗号化して送る | RFC 4187 §10.10・§10.11 | MUST |
| A-07 | AT_RESULT_IND を AT_ENCR_DATA の中に入れない | RFC 4187 §10.14 | MUST |
| A-08 | AKA-Notification は P=1 なら S=0、P=0 は認証成功後だけ、1 回の交換で 1 回だけ、成功通知は AT_RESULT_IND を使ったときだけ | RFC 4187 §6.1・§6.2 | MUST |
| A-09 | AT_BIDDING を EAP-AKA' のメッセージに入れない | RFC 9048 §4 | MUST |
| A-10 | ピアの Client-Error / Authentication-Reject の後は EAP-Failure を送る（別の Request を送らない） | RFC 4187 §6.3.1 | MUST |
| A-11 | AT_COUNTER_TOO_SMALL の後は、AKA-Identity を挟まずに Challenge を送る | RFC 4187 §5.5 | MUST |
| A-12 | EAP-AKA' の AUTN の AMF 分離ビットが 1 | RFC 9048 §3.3 | MUST |
| A-13 | AT_KDF_INPUT があり、ネットワーク名が空でない | RFC 9048 §3.1 | MUST |
| A-14 | EAP-AKA' の仮名に IMSI が含まれていない（推定による判定なので、既定は warn） | RFC 9048 §5.2 | MUST |
| A-16 | EAP-AKA/AKA' の要求の形式が正しい（既知の Subtype、未知のスキップ不可属性がない、必須属性がある） | RFC 4187 §6.3.1・§8.1 | MUST |
| A-17 | AT_KDF の再提示が、選んだ KDF を元の offer の先頭に足しただけのもの | RFC 9048 §3.2 | MUST |
| A-18 | 要求の AT_MAC があり、正しい | RFC 4187 §10.15 | MUST |
| A-19 | AT_CHECKCODE が、やりとりした AKA-Identity と一致する | RFC 4187 §10.13、RFC 9048 §3.4.3 | MUST |

違反はトレースに次の形で出力し、実行の最後に件数をまとめます。

```text
violation id=R-02 level=SHOULD action=warn ref="RFC 3579 §3.1" round=2 detail="Access-Challenge carries EAP-Message without Message-Authenticator"
conformance violations=1 fail=0 warn=1 ids=R-02
```

### ピアとしての動作

- AT_MAC は受信したバイト列のまま検証します。AUTN と SQN を確かめた後に検証します。
- 次の場合は Client-Error（コード 0）を返します。
  - AT_MAC が不正、またはない
  - 解析できない要求
  - 未知のスキップ不可属性
  - 想定外の Subtype
  - 永続 ID の要求を断るとき（`permanent_id_policy: deny` など）
- 次の場合は Authentication-Reject を返します。
  - AUTN が不正
  - EAP-AKA' で AMF の分離ビットが 0
  - 対応できる KDF がない
- EAP-AKA の Challenge の AT_BIDDING に D ビットが立っていると、`bidding_policy: reject`（既定）では Authentication-Reject を返します。判定は AT_MAC を検証した後に行い、SQN はその後に保存します。
- 使わないメソッドを提示されたら、最初の応答として Nak を返して希望するメソッドを伝えます。Nak で別のメソッドに切り替わったときは、AT_IDENTITY の先頭文字をそのメソッドの永続 ID（AKA は 0、AKA' は 6）に合わせます。
- AKA-Notification には、知らないコードでも応答します。
  - P=1（認証前）の通知には、AT_MAC なしの空の応答を返します。
  - P=0（認証後）の通知は、AT_MAC を検証してから AT_MAC 付きで応答します。
  - 失敗通知を受けた後の成功と、AT_RESULT_IND を使ったのに成功通知がない Accept は、R-05 の違反です。
- RFC 3748 の Notification（Type 2）には空の応答を返し、表示用のメッセージをトレースに出します。
- Challenge の AT_ENCR_DATA は、AT_MAC を検証した後に復号します。
  - 受け取った仮名（AT_NEXT_PSEUDONYM）は、Access-Accept を受けたら `identity_store` に保存します。
  - 復号できない、パディングが不正、未知のスキップ不可属性がある場合は、Client-Error を返します。
  - 再認証 ID（AT_NEXT_REAUTH_ID）を受け取ったら、再認証コンテキスト（鍵を含む）として保存します。認証が成功して受け取らなかったときは、再認証の状態を破棄します。
- 高速再認証（RFC 4187 §5、RFC 9048 §3.3）に対応しています。
  - AT_MAC を検証してから AT_ENCR_DATA を復号し、AT_COUNTER・AT_NONCE_S・AT_NEXT_REAUTH_ID を取り出します。
  - 新しい MSK・EMSK を導出し、暗号化した AT_COUNTER と、「パケット＋NONCE_S」に対する AT_MAC で応答します。`verify_msk` で再認証の MSK も照合できます。
  - AT_COUNTER が下限より小さければ、AT_COUNTER_TOO_SMALL で応答します。
  - 再認証の後の通知では、暗号化された AT_COUNTER を検証し、応答にも入れます。
  - 再認証コンテキストはメソッドごとに分け、別のメソッドでは使いません（RFC 9048 §7）。EAP-AKA' でネットワーク名が変わったときも使いません。
  - AT_FULLAUTH_ID_REQ には、再認証 ID ではなく永続 ID で答えます。
- AT_CHECKCODE は、AKA-Identity の Request / Response を送受信したままの形でつないで照合します。一致しなければ Client-Error を返します。
- EAP-AKA' の KDF 交渉に対応しています。offer の先頭の KDF に対応していなければ AT_KDF だけを返し、サーバの再提示を確かめます。

### 異常系の注入

ピアがわざと誤った応答を送り、サーバの異常系の処理を確かめます。

```yaml
fault:
  - { at: challenge_response, action: corrupt_mac }
```

| `at` | 使える `action` |
|---|---|
| `identity_response` | `client_error`、`auth_reject` |
| `challenge_response` | `corrupt_mac`、`wrong_res`、`client_error`、`auth_reject` |
| `reauth_response` | `corrupt_mac`、`wrong_counter`、`counter_too_small`、`client_error` |
| `start` | `reuse_reauth_id`（直近に使った再認証 ID をもう一度使う） |

- `corrupt_mac`: 応答の AT_MAC を壊す
- `wrong_res`: 誤った AT_RES を正しい AT_MAC で送る
- `client_error` / `auth_reject`: 応答を Client-Error / Authentication-Reject に差し替える

`corrupt_mac`・`wrong_res` を注入したのにサーバが成功を返した場合は、R-05 の違反になります。期待結果は通常 `reject` にします。
