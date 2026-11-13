# hostapd との相互接続テスト

hostapd 内蔵の RADIUS 認証サーバ（EAP-AKA/AKA'）と hlr_auc_gw（Milenage）を参照サーバにして、eapaka_test を動かすための環境です。テスト対象サーバに向ける前に、ツール自身の鍵導出と MSK 照合が独立した実装と一致することを確かめるのに使います（設計書 §9.3）。

## 必要なもの

- gcc、make、git
- Go（`run_cases.sh` が eapaka_test をビルドする）

hostap 内蔵の暗号実装を使うので、OpenSSL や libnl は要りません。root 権限も要りません（UDP 18120 番で待ち受けます）。

## 手順

1. hostapd と hlr_auc_gw をビルドします。`_build/` に hostap（`hostap_2_12`）を取得してビルドします。

   ```bash
   ./build.sh
   ```

   手元に hostap のクローンがあれば、`HOSTAP_URL=/path/to/hostap ./build.sh` で取得元に使えます。

2. 別の端末で hlr_auc_gw と hostapd を起動します。止めるときは Ctrl-C を押します。`HOSTAPD_DEBUG=1` を付けると hostapd のデバッグ出力が出ます。

   ```bash
   ./run.sh
   ```

3. `testdata/interop/hostapd/` のケースを実行します。ケースのファイルを引数に指定することもできます。各ケースのトレースは `_build/<ケース名>.log` に出ます。

   ```bash
   ./run_cases.sh
   ```

## ファイル

| ファイル | 内容 |
|---|---|
| `build.sh` | hostap を取得し、`hostapd.build.config` でビルドする |
| `hostapd.build.config` | RADIUS サーバと EAP-AKA/AKA' だけを有効にするビルド設定 |
| `hostapd.conf.in` | hostapd の設定（`run.sh` がパスを埋める） |
| `radius_clients` | RADIUS クライアントと共有秘密（`testing123`） |
| `eap_user` | ID の先頭文字と EAP メソッドの対応 |
| `milenage_db` | 加入者の IMSI・Ki・OPc・AMF・SQN（`configs/hostapd.yaml` の `sim` と同じ値） |
| `run.sh` / `run_cases.sh` | サーバの起動 / ケースの実行 |

eapaka_test 側の設定は `configs/hostapd.yaml` です。

## hostapd の動作の注意点

- **AKA-Identity**：hostapd は最初に AT_ANY_ID_REQ 付きの AKA-Identity を送ります。そのため、Challenge には AT_CHECKCODE が入ります。
- **仮名と再認証 ID**：Challenge の AT_ENCR_DATA で、仮名と再認証 ID を発行します（`eap_sim_id` の既定値）。
- **EAP-AKA の Challenge**：AT_BIDDING が入ります。ユーザーの EAP メソッドの一覧で AKA' が AKA より先にあれば、D ビットが立ちます。`eap_user` では AKA' の永続 ID（先頭 6）に `AKA',AKA` を許しています。そのため、ピアが Nak で AKA を希望すると、D ビット付きの AKA の Challenge になります（bidding の試験）。
- **EAP-AKA' のネットワーク名**：hostapd は "WLAN" に固定しています。
- **再認証**：再認証 ID も永続 ID ごとに 1 つで、フル認証のたびに置き換わります。再認証のケースは番号付きの名前（`reauth_1_issue` → `reauth_5_counter_too_small`）の順に流してください。使用済みの再認証 ID を受けると、hostapd は AT_FULLAUTH_ID_REQ を送ってフル認証にします。
- **仮名は永続 ID ごとに 1 つ**：同じ IMSI でフル認証をするたびに、新しく発行した仮名で置き換わります。`pseudonym_issue` で保存した仮名を `pseudonym_use` で使うので、ケースはファイル名の順（`pseudonym_issue` → `pseudonym_use`）に、間に同じ IMSI の認証を挟まずに流してください。hostapd を再起動しても仮名は消えます。
- **ピアの AT_MAC が不正なとき**：EAP-Failure の前に、認証前の失敗通知（16384）を送ります（`notification_failure_before_auth`）。
- **AT_RESULT_IND**：`eap_sim_aka_result_ind=1` で有効にしています。ピアも使えば、EAP-Success の前に成功通知（32768）を送ります。
- **SQN**：hlr_auc_gw は起動のたびに `milenage_db` の SQN から数え直します。そのため、`configs/hostapd.yaml` ではピアの SQN ストアをメモリに置いています。
