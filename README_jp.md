# eapaka_test

[English](README.md) | [日本語](README_jp.md)

RADIUS 経由で EAP-AKA / EAP-AKA' を実行する、サーバ自動テスト向け CLI ツールです。
外部利用者向けの概要と使い方を本 README にまとめています。

## 目的と特徴

- RADIUS/EAP-AKA/AKA' サーバの統合テストを CLI で簡単に実行
- EAP-AKA / EAP-AKA' の両方に対応
- outer/inner identity を分離して管理
- `AT_PERMANENT_ID_REQ` に即時応答（ポリシー指定可）
- SQN を永続化して連続実行時の同期を維持
- MPPE キーの presence check と一致検証に対応

## 必要環境

- Go 1.27.4 以上

## ビルド

```bash
go build -o eapaka_test ./cmd/eapaka_test
```

## クイックスタート

1. 設定ファイルを用意（例: `configs/example.yaml`）
2. テストケースを用意（例: `testdata/cases/success_aka.yaml`）
3. 実行

```bash
./eapaka_test -c configs/example.yaml run testdata/cases/success_aka.yaml
```

パケットキャプチャで実通信を確認したい場合は、WSL 環境での手順を `USER_GUIDE_jp.md` の項目9に記載しています。

## 終了コード

- 0: PASS（期待結果と一致）
- 1: FAIL（期待結果不一致）
- 2: ERROR（設定不備、通信エラー、パース不能など）

## ユーザーガイド

詳細なオプションやテストケース仕様は `USER_GUIDE_jp.md` を参照してください。

## 最近の更新 (2026-11-14)

- 必要な Go のバージョンを 1.27.4 に上げました。
- `go-eapaka` 依存を `v0.3.0` に更新しました。仮名認証・高速再認証・EAP-Notification・AT_BIDDING に対応するための部品が追加された版です。この更新だけでは `eapaka_test` の動作は変わりません。
  - `github.com/oyaguma3/go-eapaka`:
    `v0.0.0-20260222130953-db627581125a` →
    `v0.3.0`

## 最近の更新 (2026-02-20)

- `go-eapaka` 依存を更新し、`AT_RAND` / `AT_AUTN` の RFC 準拠修正や属性バリデーション強化を取り込みました。
  - `github.com/oyaguma3/go-eapaka`:
    `v0.0.0-20260111164821-550c12572f6d` →
    `v0.0.0-20260220135024-5edf0d7a8e21`
- `expect.reject_hint_check_presence` の規定値を `true` から `false` に変更しました。
  - 一般的な運用（Reply-Message を返さない reject）でも、`reject_hint_contains` 指定時に不要な FAIL を避けます。
  - 従来の厳格チェックが必要な場合は、ケースで `reject_hint_check_presence: true` を明示してください。
