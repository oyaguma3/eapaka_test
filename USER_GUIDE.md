# User Guide

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
  - `aka_prime.net_name`: AKA' の Network Name（fallback）

- `identity.realm`: Permanent ID 生成に使用する realm

- `sim.*`: USIM パラメータ
  - `imsi`
  - `ki`（16 bytes hex）
  - `opc`（16 bytes hex）
  - `amf`（2 bytes hex）
  - `sqn_initial_hex`（48 bit / 12 hex）

- `sqn_store.*`: SQN 永続化
  - `mode`: `file|memory`
  - `path`: file モード時に必須

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

- `sqn.reset`: SQN 初期化
- `sqn.persist`: 永続化を行うか（未指定は true）

- `expect.*`: 期待結果
  - `result`: `accept|reject`
  - `reject_hint_contains`: Reply-Message の部分一致
  - `mppe.require_present`: MPPE 属性の存在確認
  - `mppe.send_key` / `mppe.recv_key`: `hex:` / `b64:` で固定値一致

- `trace.*`: トレース
  - `level`: `normal|verbose`
  - `unsafe_log`: 機密情報のマスク解除（CI では非推奨）
  - `dump_eap_hex`: EAP hex dump 出力（verbose 時のみ）
  - `dump_radius_attrs`: RADIUS 属性一覧出力（verbose 時のみ）
  - `save_path`: トレース出力先ファイル

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
