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
  - `aka_prime.net_name`: AKA' network name fallback

- `identity.realm`: realm used to build Permanent ID

- `sim.*`: USIM parameters
  - `imsi`
  - `ki` (16-byte hex)
  - `opc` (16-byte hex)
  - `amf` (2-byte hex)
  - `sqn_initial_hex` (48-bit / 12 hex chars)

- `sqn_store.*`: SQN persistence
  - `mode`: `file|memory`
  - `path`: required when `mode=file`

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

- `sqn.reset`: reset SQN
- `sqn.persist`: whether to persist SQN (default: true)

- `expect.*`: expected result
  - `result`: `accept|reject`
  - `reject_hint_contains`: substring check against `Reply-Message`
  - `reject_hint_check_presence`: require `Reply-Message` when `reject_hint_contains` is used (default: false)
  - `mppe.require_present`: require MPPE attributes
  - `mppe.send_key` / `mppe.recv_key`: exact match (`hex:` or `b64:`)

- `trace.*`: tracing
  - `level`: `normal|verbose`
  - `unsafe_log`: disable masking (not recommended in CI)
  - `dump_eap_hex`: dump EAP hex (verbose only)
  - `dump_radius_attrs`: dump RADIUS attributes (verbose only)
  - `save_path`: output trace file path

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
