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

func TestLoadBytesRejectHintCheckPresence(t *testing.T) {
	yaml := []byte(`version: 1
name: reject_without_reply_message
identity: "0440100123456789@wlan.mnc010.mcc440.3gppnetwork.org"
expect:
  result: reject
  reject_hint_contains: "not allowed"
  reject_hint_check_presence: false
`)
	c, err := LoadBytes(yaml)
	if err != nil {
		t.Fatalf("expected valid testcase, got error: %v", err)
	}
	if c.Expect.RejectHintCheckPresence == nil {
		t.Fatalf("expected reject_hint_check_presence to be parsed")
	}
	if *c.Expect.RejectHintCheckPresence {
		t.Fatalf("expected reject_hint_check_presence=false")
	}
}

func TestValidateFaults(t *testing.T) {
	base := Case{Version: 1, Identity: "user", Expect: Expect{Result: "reject"}}
	tests := []struct {
		fault   Fault
		wantErr bool
	}{
		{Fault{At: "challenge_response", Action: "corrupt_mac"}, false},
		{Fault{At: "identity_response", Action: "client_error"}, false},
		{Fault{At: "identity_response", Action: "corrupt_mac"}, true},
		{Fault{At: "reauth_response", Action: "corrupt_mac"}, false},
		{Fault{At: "reauth_response", Action: "wrong_res"}, true},
		{Fault{At: "notification_response", Action: "corrupt_mac"}, true},
	}
	for _, tt := range tests {
		c := base
		c.Faults = []Fault{tt.fault}
		if err := c.Validate(); (err != nil) != tt.wantErr {
			t.Errorf("Validate(%+v) error = %v, wantErr %t", tt.fault, err, tt.wantErr)
		}
	}
}

func TestValidateConformanceRules(t *testing.T) {
	c := Case{Version: 1, Identity: "user", Expect: Expect{Result: "accept"}}
	c.Conformance.Rules = map[string]string{"R-02": "fail"}
	if err := c.Validate(); err != nil {
		t.Errorf("valid rules rejected: %v", err)
	}
	c.Conformance.Rules = map[string]string{"R-99": "fail"}
	if err := c.Validate(); err == nil {
		t.Error("unknown rule accepted")
	}
	c.Conformance.Rules = map[string]string{"R-02": "error"}
	if err := c.Validate(); err == nil {
		t.Error("unknown action accepted")
	}
}
