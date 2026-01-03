# eapaka_test

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

- Go 1.25.x（1.25 以上）

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

パケットキャプチャで実通信を確認したい場合は、WSL 環境での手順を `USER_GUIDE.md` の項目9に記載しています。

## 終了コード

- 0: PASS（期待結果と一致）
- 1: FAIL（期待結果不一致）
- 2: ERROR（設定不備、通信エラー、パース不能など）

## ユーザーガイド

詳細なオプションやテストケース仕様は `USER_GUIDE.md` を参照してください。
