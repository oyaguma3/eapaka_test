# eapaka_test

[English](README.md) | [Japanese](README_jp.md)

`eapaka_test` is a CLI tool for automated server testing of EAP-AKA / EAP-AKA' over RADIUS.
This README provides a quick overview for external users.

## Purpose and Features

- Run integration tests for RADIUS/EAP-AKA/AKA' servers from CLI
- Support both EAP-AKA and EAP-AKA'
- Manage outer/inner identities separately
- Immediately handle `AT_PERMANENT_ID_REQ` (policy configurable)
- Persist SQN state across runs
- Verify MPPE key presence and optional exact value matching

## Requirements

- Go 1.25.x (1.25 or newer)

## Build

```bash
go build -o eapaka_test ./cmd/eapaka_test
```

## Quick Start

1. Prepare a config file (example: `configs/example.yaml`)
2. Prepare a test case file (example: `testdata/cases/success_aka.yaml`)
3. Run

```bash
./eapaka_test -c configs/example.yaml run testdata/cases/success_aka.yaml
```

If you need packet capture in WSL, see section 9 in `USER_GUIDE.md`.

## Exit Codes

- 0: PASS (matches expected result)
- 1: FAIL (expected/actual mismatch)
- 2: ERROR (invalid config, communication error, parse error, etc.)

## Guides

- English guide: `USER_GUIDE.md`
- Japanese guide: `USER_GUIDE_jp.md`

## Recent Updates (2026-02-20)

- Updated `go-eapaka` dependency to include RFC-compliant `AT_RAND`/`AT_AUTN` handling and stronger attribute validation.
  - `github.com/oyaguma3/go-eapaka`:
    `v0.0.0-20260111164821-550c12572f6d` ->
    `v0.0.0-20260220135024-5edf0d7a8e21`
- Changed default `expect.reject_hint_check_presence` from `true` to `false`.
  - This avoids unnecessary FAIL when reject responses do not include `Reply-Message` in common deployments.
  - For strict behavior, set `reject_hint_check_presence: true` in each case.
