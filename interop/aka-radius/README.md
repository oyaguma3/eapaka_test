# テスト対象サーバ（aka-radius＋aka-vecgen）との接続テスト

テスト対象サーバの aka-radius と、認証ベクタを作る aka-vecgen を WSL2 の中に立てて、eapaka_test のケースを流すための手順です。構成は aka-mvpset の `verify/stage2`（段階 2 の通しの試験）をそのまま使います。

hostapd（`interop/hostapd/`）は、ツール自身が正しいかを確かめる参照サーバです。こちらは、テスト対象サーバの実装を確かめるのに使います（設計書 §9）。

## 構成

```text
eapaka_test ──UDP──▶ edge-t42（radsecproxy。テナント 42 の刻印を付ける）──RadSec──▶ aka-radius auth ──mTLS──▶ aka-vecgen
           127.0.0.1:11812
```

- aka-radius は、テナントの刻印（Vendor-Specific 32473/1）のない要求を拒否します。そのため、eapaka_test は aka-radius（1812）に直接ではなく、エッジの代わり（11812）に送ります。共有秘密は `ap-secret-0123456789` です。
- 加入者は `stage2.sh` が登録するものを使います。いずれもテナント 42 です。
  - EAP-AKA は 440100000000001
  - EAP-AKA' は 440100000000002
- 作業場所は `~/aka-work/stage2`（環境変数 `AKA_WORK` で変えられます）です。各リポジトリには何も書き込みません。

## 必要なもの

- Docker（Docker Desktop の WSL 統合など）、Go、openssl、python3、curl
- 次のリポジトリのクローン。既定は `~/projects/` の下で、`MVPSET_DIR`・`RADIUS_DIR`・`VECGEN_DIR` で変えられます。
  - [aka-mvpset](https://github.com/oyaguma3/aka-mvpset)：`verify/stage2` の compose・エッジの設定・`stage2.sh` を使う
  - [aka-radius](https://github.com/oyaguma3/aka-radius)
  - [aka-vecgen](https://github.com/oyaguma3/aka-vecgen)

組み合わせる版は、aka-mvpset の `versions.env` を目安にします。

## 手順

すべて `interop/aka-radius/ctl.sh` で操作します。

### 初回

1. 手元のクローンから、イメージ `aka-radius:dev`、`aka-vecgen:stage2`、`stage2-tools:dev` をビルドします。aka-radius を直したときも、これでイメージを作り直します。

   ```bash
   ./ctl.sh images
   ```

2. 作業場所を作り、`stage2.sh` の準備部分（EAP の試験の手前まで）を動かします。内容は次のとおりで、数分かかります。
   - 起動
   - mTLS の証明書を作る
   - 加入者と RADIUS クライアントを登録する

   最後に `S0 PASS` と出れば成功です。

   ```bash
   ./ctl.sh setup
   ```

### 使うとき

```bash
./ctl.sh up
```

```bash
./ctl.sh run
```

```bash
./ctl.sh down
```

- `run` は、`testdata/interop/aka-radius/aka/` のケースを `configs/aka-radius-aka.yaml` で流します。`aka_prime/` のケースは `configs/aka-radius-aka-prime.yaml` で流します。
- ケースのファイルを引数に指定することもできます。
- トレースは `_build/<方式>-<ケース名>.log` に出ます。
- `down` に `-v` を付けないと、Valkey のボリュームが残ります。登録（加入者、RADIUS クライアント、証明書のピン）を残したまま止められます。
- `restart: always` のコンテナがあるので、止めるときは `docker compose stop` ではなく `down` を使ってください。`stop` だと、Docker を再起動したときに立ち上がってしまいます。

### aka-radius を直した後

```bash
./ctl.sh images && ./ctl.sh up && ./ctl.sh run
```

`up` は、新しいイメージで auth と acct を作り直します。

### 作り直し

```bash
./ctl.sh down -v && ./ctl.sh setup
```

`stage2.sh` が作るクライアント証明書は、30 日で切れます。aka-radius が aka-vecgen に接続する `vecgen-client.pem` と、管理 API を呼ぶ `prov.pem` です。期限は `./ctl.sh status` で確認できます。切れた後は、上のコマンドで作り直してください。

## ケース

| 方式 | ケース | 期待 |
|---|---|---|
| EAP-AKA | `msk_verify_full` | Access-Accept。MS-MPPE 鍵を復号した値が MSK と一致する |
| EAP-AKA | `fault_client_error` | Challenge に Client-Error で応答すると Access-Reject |
| EAP-AKA | `fault_corrupt_mac` | Challenge 応答の AT_MAC を壊すと Access-Reject |
| EAP-AKA' | `msk_verify_full` | Access-Accept。MSK と一致する |
| EAP-AKA' | `fault_client_error` | Access-Reject |
| EAP-AKA' | `fault_wrong_res` | 誤った AT_RES を正しい AT_MAC で送ると Access-Reject |

## 既知の違反（2026-11-14 時点）

aka-radius `b85cd68` では、すべてのケースで R-04（MUST）の違反が出て、終了コードは 1 になります。

- **内容**：aka-radius が、EAP-Success/Failure の Identifier を「直前の EAP-Response の Identifier + 1」にしています。RFC 3748 §4.2 では、Response の Identifier と一致させなければなりません。
- **違反以外の結果**：期待結果（accept / reject）と MSK 照合は一致しています。
- **一時的に通したいとき**：設定ファイルかケースに `conformance: { rules: { R-04: warn } }` を足してください。
