# User Guide

[English](USER_GUIDE.md) | [Japanese](USER_GUIDE_jp.md)

This document explains how to use `eapaka_test`.

## 1. Run Command

```bash
./eapaka_test -c <config.yaml> run <case.yaml>
```

## 2. CLI Options

- `-c <path>`: config file path (required)
- `run <case>`: test case file path (required)
- `--unsafe-log`: print sensitive values (RAND/AUTN/RES, etc.) without masking
- `--trace-eap-hex`: force EAP hex dump in verbose mode
- `--trace-radius-attrs`: force RADIUS attribute dump in verbose mode

## 3. Config File

Example: `configs/example.yaml`

### Example

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

Main fields:

- `radius.server_addr`: `<host>:<port>`
- `radius.secret`: RADIUS shared secret
- `radius.timeout_ms`: timeout in milliseconds
- `radius.retries`: retry count

- `radius_attrs.*`: optional extra RADIUS attributes
  - `nas_ip_address`
  - `nas_identifier`
  - `called_station_id` (format below)
  - `calling_station_id`

- `eap.*`: EAP policies
  - `method_mismatch_policy`: `strict|warn|allow`
  - `outer_identity_update_on_permanent_req`: `true|false`
  - `permanent_id_policy`: `always|conservative|deny`
  - `aka_prime.net_name`: AKA' network name, used by `net_name_check` and by `empty_kdf_input: fallback`
  - `aka_prime.net_name_check`: `off|warn|reject` (default: off). Compares AT_KDF_INPUT with `net_name` field by field (colon-separated). On mismatch, warn only logs; reject sends Authentication-Reject
  - `aka_prime.empty_kdf_input`: `reject|fallback` (default: reject). When AT_KDF_INPUT is missing or empty, send Authentication-Reject or continue with `net_name`. Either way it is recorded as violation A-13

- `identity.realm`: realm used to build Permanent ID

- `sim.*`: USIM parameters
  - `imsi`
  - `ki` (16-byte hex)
  - `opc` (16-byte hex)
  - `amf` (2-byte hex). A different AMF in AUTN only produces a warning
  - `sqn_initial_hex` (48-bit / 12 hex chars)

- `sqn_store.*`: SQN persistence
  - `mode`: `file|memory`
  - `path`: required when `mode=file`

- `conformance.*`: server conformance checks (section 10)
  - `default_must`: handling of MUST rules, `fail|warn|off` (default: fail)
  - `default_should`: handling of SHOULD rules, `fail|warn|off` (default: warn)
  - `rules`: per-rule overrides (e.g. `{ R-02: off }`)

- `mppe.mapping`: how MS-MPPE keys map to the MSK, `rfc5216` (default; Recv-Key = MSK[0:32], Send-Key = MSK[32:64]) or `swapped`

## 4. Test Case File

Example: `testdata/cases/success_aka.yaml`

### Example

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

Main fields:

- `identity`: initial outer identity (required)
- `radius.*`: optional per-case override for radius settings
- `eap.*`: optional per-case override for eap settings
  - `permanent_identity_override`: fully override Permanent ID
  - `aka_prime.net_name_check` / `aka_prime.empty_kdf_input`: same as in config

- `sqn.reset`: reset SQN
- `sqn.persist`: whether to persist SQN (default: true)

- `expect.*`: expected result
  - `result`: `accept|reject`
  - `reject_hint_contains`: substring check against `Reply-Message`
  - `reject_hint_check_presence`: require `Reply-Message` when `reject_hint_contains` is used (default: false)
  - `mppe.require_present`: require MPPE attributes
  - `mppe.send_key` / `mppe.recv_key`: exact match (`hex:` or `b64:`)
  - `mppe.verify_msk`: decrypt the MS-MPPE keys and require them to match the MSK derived by the peer (section 6)

- `trace.*`: tracing
  - `level`: `normal|verbose`
  - `unsafe_log`: disable masking (not recommended in CI)
  - `dump_eap_hex`: dump EAP hex (verbose only)
  - `dump_radius_attrs`: dump RADIUS attributes (verbose only)
  - `save_path`: output trace file path

- `conformance.rules`: per-case rule handling (e.g. temporarily set a known violation to `warn` during development)
- `fault`: faults injected by the peer (section 10)

## 5. `called_station_id` Format

Recommended format:

- `xx-xx-xx-xx-xx-xx:MySSID`
  - MAC part must be fixed 17 chars
  - `:` must appear exactly once

Verbose trace warns when format is invalid.

## 6. MPPE Handling

- Access-Accept must include `MS-MPPE-Send-Key` and `MS-MPPE-Recv-Key`
- Default operation is `require_present: true` (presence check)
- Exact value matching is intended only for fixed test vectors
- With `verify_msk: true`, the tool decrypts the MS-MPPE keys and compares them with the MSK derived by the peer, using `mppe.mapping` in the config. Unlike the encrypted values, which change with the Request Authenticator and Salt, this works for every run. The trace shows only whether they match; key values are never written, even with `--unsafe-log`.
- Interop testing against hostapd is described in `interop/hostapd/README.md`.

## 7. Common Usage

```bash
./eapaka_test -c configs/example.yaml run testdata/cases/perm_id_req_from_pseudonym.yaml
./eapaka_test -c configs/example.yaml --unsafe-log run testdata/cases/success_aka.yaml
```

## 8. Notes

- `--unsafe-log` / `trace.unsafe_log: true` exposes sensitive data; avoid in CI.
- With `sqn_store.mode=file`, do not share the same `path` across concurrent processes.
- `method_mismatch_policy=strict` fails on EAP method mismatch; ensure case data is consistent.

## 9. Capturing RADIUS Packets in WSL

When running both `eapaka_test` and your RADIUS server inside WSL2 (Ubuntu), loopback traffic is often invisible from Windows capture interfaces. Capture inside WSL for reliability.

### Method A: Capture in WSL and open on Windows Wireshark (recommended)

1. Install tcpdump

```bash
sudo apt update
sudo apt install -y tcpdump
```

2. Start capture in WSL (`lo` is best for local WSL traffic)

```bash
sudo tcpdump -i lo -w /mnt/c/Users/<WindowsUser>/Desktop/radius.pcap 'udp port 1812 or 1813'
```

3. Run `eapaka_test` and generate traffic
4. Stop capture with Ctrl+C and open `radius.pcap` in Windows Wireshark

### Method B: Capture directly with WSL Wireshark GUI

1. Install Wireshark

```bash
sudo apt update
sudo apt install -y wireshark
```

2. Grant capture permissions (or run `sudo wireshark`)

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
sudo usermod -aG wireshark $USER
```

3. Re-login, launch Wireshark, and capture on `lo` (or `any`)
4. Use display filter `udp.port == 1812 || udp.port == 1813`

## 10. Server Conformance Checks and Fault Injection

### Conformance checks

The tool can fail a run on server RFC violations even when the result matches the expectation. Violations are recorded per rule, and each rule is handled as `fail`, `warn` or `off` (default: fail for MUST, warn for SHOULD). One `fail` violation makes the exit code 1 even if the expected result matched.

| ID | Check | Reference | Level |
|---|---|---|---|
| R-01 | Message-Authenticator in a response is valid | RFC 3579 §3.2 | MUST |
| R-02 | A response carrying EAP-Message includes Message-Authenticator | RFC 3579 §3.1 | SHOULD |
| R-03a | Access-Accept carries EAP-Success and Access-Reject carries EAP-Failure | RFC 3579 §2.6.3 | SHOULD |
| R-03b | Access-Challenge carries an EAP-Request | RFC 3579 §2.1 | MUST |
| R-04 | EAP-Success/Failure Identifier matches the last EAP-Response | RFC 3748 §4.2 | MUST |
| R-05 | No success indication before the method completes or after it failed | RFC 3748 §4.2, RFC 4187 §6.2 | MUST |
| R-06 | The server does not switch EAP types during a method | RFC 3748 §2.1 | MUST |
| R-07 | MS-MPPE key Salts have the MSB set and differ between Send and Recv | RFC 2548 §2.4.2 | MUST |
| A-12 | The AMF separation bit in EAP-AKA' AUTN is 1 | RFC 9048 §3.3 | MUST |
| A-13 | AT_KDF_INPUT is present with a non-empty network name | RFC 9048 §3.1 | MUST |
| A-16 | EAP-AKA/AKA' requests are well-formed (known subtype, no unknown non-skippable attribute, required attributes present) | RFC 4187 §6.3.1, §8.1 | MUST |
| A-17 | An AT_KDF re-offer only prepends the selected KDF to the original offer | RFC 9048 §3.2 | MUST |
| A-18 | AT_MAC in a request is present and valid | RFC 4187 §10.15 | MUST |

Violations are written to the trace as follows, with a summary at the end of the run:

```text
violation id=R-02 level=SHOULD action=warn ref="RFC 3579 §3.1" round=2 detail="Access-Challenge carries EAP-Message without Message-Authenticator"
conformance violations=1 fail=0 warn=1 ids=R-02
```

### Peer behavior

- AT_MAC is verified over the received bytes, after AUTN and SQN have been checked.
- The peer sends Client-Error (code 0) in these cases:
  - AT_MAC is invalid or missing
  - The request cannot be parsed
  - The request has an unknown non-skippable attribute
  - The request has an unexpected subtype
  - The peer declines a permanent identity request (for example, `permanent_id_policy: deny`)
- The peer sends Authentication-Reject in these cases:
  - AUTN is invalid
  - The EAP-AKA' AMF separation bit is 0
  - No offered KDF is supported
- EAP-AKA' KDF negotiation is supported. If the first offered KDF is not supported, the peer replies with only AT_KDF and validates the server's re-offer.

### Fault injection

The peer can intentionally send invalid responses to test the server's error handling.

```yaml
fault:
  - { at: challenge_response, action: corrupt_mac }
```

| `at` | Allowed `action` |
|---|---|
| `identity_response` | `client_error`, `auth_reject` |
| `challenge_response` | `corrupt_mac`, `wrong_res`, `client_error`, `auth_reject` |

- `corrupt_mac`: corrupt AT_MAC in the response
- `wrong_res`: send a wrong AT_RES with a valid AT_MAC
- `client_error` / `auth_reject`: replace the response with Client-Error / Authentication-Reject

If the server still reports success after `corrupt_mac` or `wrong_res`, it is recorded as an R-05 violation. Such cases normally expect `reject`.
