package config

import "testing"

func TestLoadBytesDefaults(t *testing.T) {
	yaml := []byte(`radius:
  server_addr: "127.0.0.1:1812"
  secret: "testing123"
identity:
  realm: "wlan.mnc010.mcc440.3gppnetwork.org"
sim:
  imsi: "440100123456789"
  ki: "00112233445566778899aabbccddeeff"
  opc: "00112233445566778899aabbccddeeff"
  amf: "8000"
  sqn_initial_hex: "000000000000"
sqn_store:
  path: "/tmp/eapaka_test-sqn.json"
`)
	cfg, err := LoadBytes(yaml)
	if err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
	if cfg.Radius.TimeoutMS != DefaultTimeoutMS {
		t.Fatalf("expected timeout default %d, got %d", DefaultTimeoutMS, cfg.Radius.TimeoutMS)
	}
	if cfg.Radius.Retries != DefaultRetries {
		t.Fatalf("expected retries default %d, got %d", DefaultRetries, cfg.Radius.Retries)
	}
	if cfg.EAP.MethodMismatchPolicy != DefaultMethodMismatchPolicy {
		t.Fatalf("expected mismatch policy default %q, got %q", DefaultMethodMismatchPolicy, cfg.EAP.MethodMismatchPolicy)
	}
	if cfg.EAP.PermanentIDPolicy != DefaultPermanentIDPolicy {
		t.Fatalf("expected permanent policy default %q, got %q", DefaultPermanentIDPolicy, cfg.EAP.PermanentIDPolicy)
	}
	if cfg.EAP.OuterIdentityUpdateOnPermanentReq == nil || !*cfg.EAP.OuterIdentityUpdateOnPermanentReq {
		t.Fatalf("expected outer identity update default true")
	}
	if cfg.SQNStore.Mode != "file" {
		t.Fatalf("expected default sqn_store.mode file, got %q", cfg.SQNStore.Mode)
	}
}

func TestLoadBytesInvalidHex(t *testing.T) {
	yaml := []byte(`radius:
  server_addr: "127.0.0.1:1812"
  secret: "testing123"
sim:
  imsi: "440100123456789"
  ki: "00112233445566778899aabbccddeeff"
  opc: "00112233445566778899aabbccddeeff"
  amf: "800"
  sqn_initial_hex: "000000000000"
sqn_store:
  path: "/tmp/eapaka_test-sqn.json"
`)
	_, err := LoadBytes(yaml)
	if err == nil {
		t.Fatalf("expected error for invalid amf length")
	}
}
