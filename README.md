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

- Go 1.27.4 or newer

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
- 1: FAIL (expected/actual mismatch, or a server conformance violation handled as `fail`)
- 2: ERROR (invalid config, communication error, parse error, etc.)

## Guides

- English guide: `USER_GUIDE.md`
- Japanese guide: `USER_GUIDE_jp.md`

## Recent Updates (2026-11-14)

- Raised the required Go version to 1.27.4.
- Updated `go-eapaka` dependency to `v0.3.0`, which adds the building blocks for pseudonyms, fast re-authentication, EAP-Notification and AT_BIDDING. This update alone does not change the behavior of `eapaka_test`.
  - `github.com/oyaguma3/go-eapaka`:
    `v0.0.0-20260222130953-db627581125a` ->
    `v0.3.0`
- Added server conformance checks (RFC 3579/3748/2548/4187/9048). A violation handled as `fail` makes the run exit 1 even when the expected result matches. See section 10 of `USER_GUIDE.md`.
- Aligned the peer with RFC 4187 and RFC 9048. This changes behavior:
  - An invalid AT_MAC or a declined permanent identity request now gets Client-Error instead of Authentication-Reject.
  - AT_MAC is verified over the received bytes, after AUTN.
  - EAP-AKA' KDF negotiation now replies with only AT_KDF.
  - A missing or empty AT_KDF_INPUT is rejected by default. Set `eap.aka_prime.empty_kdf_input: fallback` to keep the old behavior.
  - An AMF different from `sim.amf` is now only a warning. For EAP-AKA', the AMF separation bit is checked instead.
- Added fault injection (`fault` in testcases).
- Added MSK verification: `expect.mppe.verify_msk: true` decrypts MS-MPPE-Send/Recv-Key and compares them with the MSK derived by the peer.
- Added AKA-Notification, AT_RESULT_IND and RFC 3748 Notification (Type 2), with rules A-08 and A-10. Verified against hostapd 2.12 with result indication enabled.
- Added AT_BIDDING handling (RFC 9048 §4) and EAP Nak with method preference and forced Nak, which can steer a server to EAP-AKA for bidding-down tests. Verified against hostapd 2.12.
- Added an interop environment with hostapd as the reference server (`interop/hostapd/`). Full authentication with EAP-AKA and EAP-AKA' passes MSK verification against hostapd 2.12.

## Recent Updates (2026-02-20)

- Updated `go-eapaka` dependency to include RFC-compliant `AT_RAND`/`AT_AUTN` handling and stronger attribute validation.
  - `github.com/oyaguma3/go-eapaka`:
    `v0.0.0-20260111164821-550c12572f6d` ->
    `v0.0.0-20260220135024-5edf0d7a8e21`
- Changed default `expect.reject_hint_check_presence` from `true` to `false`.
  - This avoids unnecessary FAIL when reject responses do not include `Reply-Message` in common deployments.
  - For strict behavior, set `reject_hint_check_presence: true` in each case.
