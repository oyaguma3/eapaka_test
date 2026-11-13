# User Guide

[English](USER_GUIDE.md) | [日本語](USER_GUIDE_jp.md)

このドキュメントは外部利用者向けの使い方ガイドです。

## 1. 実行方法

```bash
./eapaka_test -c <config.yaml> run <case.yaml>
```

## 2. CLI オプション

- `-c <path>`: 設定ファイル（必須）
- `run <case>`: テストケースファイル（必須）
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

- `identity`: 開始時の outer identity（必須）
- `radius.*`: config を上書きする RADIUS 設定（任意）
- `eap.*`: config を上書きする EAP 設定（任意）
  - `permanent_identity_override`: Permanent ID の完全指定
  - `aka_prime.net_name_check` / `aka_prime.empty_kdf_input`: config と同じ

- `sqn.reset`: SQN 初期化
- `sqn.persist`: 永続化を行うか（未指定は true）

- `expect.*`: 期待結果
  - `result`: `accept|reject`
  - `reject_hint_contains`: Reply-Message の部分一致
  - `reject_hint_check_presence`: `reject_hint_contains` 使用時に Reply-Message 必須とするか（既定: false）
  - `mppe.require_present`: MPPE 属性の存在確認
  - `mppe.send_key` / `mppe.recv_key`: `hex:` / `b64:` で固定値一致
  - `mppe.verify_msk`: MS-MPPE 鍵を復号し、ピアが導出した MSK と一致することを求める（第 6 章）

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
| A-12 | EAP-AKA' の AUTN の AMF 分離ビットが 1 | RFC 9048 §3.3 | MUST |
| A-13 | AT_KDF_INPUT があり、ネットワーク名が空でない | RFC 9048 §3.1 | MUST |
| A-16 | EAP-AKA/AKA' の要求の形式が正しい（既知の Subtype、未知のスキップ不可属性がない、必須属性がある） | RFC 4187 §6.3.1・§8.1 | MUST |
| A-17 | AT_KDF の再提示が、選んだ KDF を元の offer の先頭に足しただけのもの | RFC 9048 §3.2 | MUST |
| A-18 | 要求の AT_MAC があり、正しい | RFC 4187 §10.15 | MUST |

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

- `corrupt_mac`: 応答の AT_MAC を壊す
- `wrong_res`: 誤った AT_RES を正しい AT_MAC で送る
- `client_error` / `auth_reject`: 応答を Client-Error / Authentication-Reject に差し替える

`corrupt_mac`・`wrong_res` を注入したのにサーバが成功を返した場合は、R-05 の違反になります。期待結果は通常 `reject` にします。
