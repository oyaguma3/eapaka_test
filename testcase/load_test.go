package testcase

import "testing"

func TestLoadBytesValid(t *testing.T) {
	yaml := []byte(`version: 1
name: success_aka
identity: "0440100123456789@wlan.mnc010.mcc440.3gppnetwork.org"
expect:
  result: accept
  mppe:
    require_present: true
`)
	_, err := LoadBytes(yaml)
	if err != nil {
		t.Fatalf("expected valid testcase, got error: %v", err)
	}
}

func TestLoadBytesMissingIdentity(t *testing.T) {
	yaml := []byte(`version: 1
name: missing_identity
expect:
  result: accept
`)
	_, err := LoadBytes(yaml)
	if err == nil {
		t.Fatalf("expected error for missing identity")
	}
}

func TestLoadBytesInvalidMPPEPrefix(t *testing.T) {
	yaml := []byte(`version: 1
name: mppe_bad
identity: "0440100123456789@wlan.mnc010.mcc440.3gppnetwork.org"
expect:
  result: accept
  mppe:
    send_key: "raw:deadbeef"
`)
	_, err := LoadBytes(yaml)
	if err == nil {
		t.Fatalf("expected error for invalid mppe prefix")
	}
}
