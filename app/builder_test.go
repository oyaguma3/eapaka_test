package app

import (
	"testing"

	"github.com/oyaguma3/eapaka_test/config"
	"github.com/oyaguma3/eapaka_test/eap"
	"github.com/oyaguma3/eapaka_test/testcase"

	eapaka "github.com/oyaguma3/go-eapaka"
)

func TestBuildPeerPermanentOverride(t *testing.T) {
	outerUpdate := false
	cfg := config.Config{
		EAP: config.EAPConfig{
			MethodMismatchPolicy:              "warn",
			OuterIdentityUpdateOnPermanentReq: &outerUpdate,
			PermanentIDPolicy:                 "always",
			AKAPrime: config.AKAPrimeConfig{
				NetName: "wlan.example",
			},
		},
		Identity: config.IdentityConfig{Realm: "wlan.example"},
		SIM: config.SIMConfig{
			IMSI:          "440100123456789",
			KI:            "00112233445566778899aabbccddeeff",
			OPC:           "00112233445566778899aabbccddeeff",
			AMF:           "8000",
			SQNInitialHex: "000000000000",
		},
	}

	caseData := testcase.Case{
		Identity: "2pseudonym@example",
		EAP: testcase.EAP{
			PermanentIDPolicy:                 "always",
			PermanentIdentityOverride:         "0440100123456789@wlan.example",
			OuterIdentityUpdateOnPermanentReq: &outerUpdate,
		},
		Expect:  testcase.Expect{Result: "accept"},
		Version: 1,
	}

	peer, err := BuildPeer(cfg, caseData, nil)
	if err != nil {
		t.Fatalf("build peer failed: %v", err)
	}
	if peer.Session == nil {
		t.Fatalf("expected session")
	}

	req := &eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 1,
		Type:       eapaka.TypeAKA,
		Subtype:    eapaka.SubtypeIdentity,
		Attributes: []eapaka.Attribute{&eapaka.AtPermanentIdReq{}},
	}
	raw, err := req.Marshal()
	if err != nil {
		t.Fatalf("marshal request failed: %v", err)
	}
	eapReq, err := eap.Parse(raw)
	if err != nil {
		t.Fatalf("parse request failed: %v", err)
	}

	resp, err := peer.Handle(eapReq)
	if err != nil {
		t.Fatalf("handle failed: %v", err)
	}
	respRaw, err := resp.Encode()
	if err != nil {
		t.Fatalf("encode response failed: %v", err)
	}
	akaResp, err := eapaka.Parse(respRaw)
	if err != nil {
		t.Fatalf("parse response failed: %v", err)
	}
	found := false
	for _, attr := range akaResp.Attributes {
		if idAttr, ok := attr.(*eapaka.AtIdentity); ok {
			found = true
			if idAttr.Identity != "0440100123456789@wlan.example" {
				t.Fatalf("unexpected identity %q", idAttr.Identity)
			}
		}
	}
	if !found {
		t.Fatalf("expected AT_IDENTITY")
	}
	if peer.Session.InnerIdentity != "0440100123456789@wlan.example" {
		t.Fatalf("expected inner identity updated")
	}
	if peer.Session.OuterIdentity != "2pseudonym@example" {
		t.Fatalf("expected outer identity unchanged")
	}
}
