package aka

import (
	"testing"

	"github.com/oyaguma3/eapaka_test/eap"
	eapaka "github.com/oyaguma3/go-eapaka"
)

func TestHandleIdentityResponse(t *testing.T) {
	method, err := New(Options{
		MethodType: eap.TypeAKA,
		IMSI:       "440100123456789",
		KI:         make([]byte, 16),
		OPC:        make([]byte, 16),
		AMF:        []byte{0x80, 0x00},
	})
	if err != nil {
		t.Fatalf("new method failed: %v", err)
	}

	req := &eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 1,
		Type:       eapaka.TypeAKA,
		Subtype:    eapaka.SubtypeIdentity,
	}
	raw, err := req.Marshal()
	if err != nil {
		t.Fatalf("marshal request failed: %v", err)
	}
	eapReq, err := eap.Parse(raw)
	if err != nil {
		t.Fatalf("parse request failed: %v", err)
	}

	sess := &eap.Session{OuterIdentity: "user@example"}
	resp, err := method.Handle(eapReq, sess)
	if err != nil {
		t.Fatalf("handle failed: %v", err)
	}
	rawResp, err := resp.Encode()
	if err != nil {
		t.Fatalf("encode response failed: %v", err)
	}
	akaResp, err := eapaka.Parse(rawResp)
	if err != nil {
		t.Fatalf("parse response failed: %v", err)
	}
	if akaResp.Subtype != eapaka.SubtypeIdentity {
		t.Fatalf("expected identity subtype")
	}
	found := false
	for _, attr := range akaResp.Attributes {
		if idAttr, ok := attr.(*eapaka.AtIdentity); ok {
			found = true
			if idAttr.Identity != "user@example" {
				t.Fatalf("unexpected identity %q", idAttr.Identity)
			}
		}
	}
	if !found {
		t.Fatalf("expected AT_IDENTITY in response")
	}
}

func TestHandlePermanentIDAlways(t *testing.T) {
	method, err := New(Options{
		MethodType:        eap.TypeAKA,
		IMSI:              "440100123456789",
		KI:                make([]byte, 16),
		OPC:               make([]byte, 16),
		AMF:               []byte{0x80, 0x00},
		Realm:             "wlan.mnc010.mcc440.3gppnetwork.org",
		PermanentIDPolicy: "always",
	})
	if err != nil {
		t.Fatalf("new method failed: %v", err)
	}

	req := &eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 2,
		Type:       eapaka.TypeAKA,
		Subtype:    eapaka.SubtypeIdentity,
		Attributes: []eapaka.Attribute{
			&eapaka.AtPermanentIdReq{},
		},
	}
	raw, err := req.Marshal()
	if err != nil {
		t.Fatalf("marshal request failed: %v", err)
	}
	eapReq, err := eap.Parse(raw)
	if err != nil {
		t.Fatalf("parse request failed: %v", err)
	}

	sess := &eap.Session{OuterIdentity: "2pseudonym@example"}
	resp, err := method.Handle(eapReq, sess)
	if err != nil {
		t.Fatalf("handle failed: %v", err)
	}
	rawResp, err := resp.Encode()
	if err != nil {
		t.Fatalf("encode response failed: %v", err)
	}
	akaResp, err := eapaka.Parse(rawResp)
	if err != nil {
		t.Fatalf("parse response failed: %v", err)
	}
	expected := "0440100123456789@wlan.mnc010.mcc440.3gppnetwork.org"
	found := false
	for _, attr := range akaResp.Attributes {
		if idAttr, ok := attr.(*eapaka.AtIdentity); ok {
			found = true
			if idAttr.Identity != expected {
				t.Fatalf("unexpected identity %q", idAttr.Identity)
			}
		}
	}
	if !found {
		t.Fatalf("expected AT_IDENTITY in response")
	}
	if sess.InnerIdentity != expected {
		t.Fatalf("expected inner identity to be updated")
	}
	if sess.OuterIdentity != expected {
		t.Fatalf("expected outer identity to be updated")
	}
}

func TestHandlePermanentIDDeny(t *testing.T) {
	method, err := New(Options{
		MethodType:        eap.TypeAKA,
		IMSI:              "440100123456789",
		KI:                make([]byte, 16),
		OPC:               make([]byte, 16),
		AMF:               []byte{0x80, 0x00},
		PermanentIDPolicy: "deny",
	})
	if err != nil {
		t.Fatalf("new method failed: %v", err)
	}

	req := &eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 3,
		Type:       eapaka.TypeAKA,
		Subtype:    eapaka.SubtypeIdentity,
		Attributes: []eapaka.Attribute{
			&eapaka.AtPermanentIdReq{},
		},
	}
	raw, err := req.Marshal()
	if err != nil {
		t.Fatalf("marshal request failed: %v", err)
	}
	eapReq, err := eap.Parse(raw)
	if err != nil {
		t.Fatalf("parse request failed: %v", err)
	}

	sess := &eap.Session{OuterIdentity: "2pseudonym@example"}
	resp, err := method.Handle(eapReq, sess)
	if err != nil {
		t.Fatalf("handle failed: %v", err)
	}
	rawResp, err := resp.Encode()
	if err != nil {
		t.Fatalf("encode response failed: %v", err)
	}
	akaResp, err := eapaka.Parse(rawResp)
	if err != nil {
		t.Fatalf("parse response failed: %v", err)
	}
	if akaResp.Subtype != eapaka.SubtypeAuthenticationReject {
		t.Fatalf("expected authentication reject")
	}
}

func TestHandleAnyFullauthIdReq(t *testing.T) {
	method, err := New(Options{
		MethodType: eap.TypeAKA,
		IMSI:       "440100123456789",
		KI:         make([]byte, 16),
		OPC:        make([]byte, 16),
		AMF:        []byte{0x80, 0x00},
	})
	if err != nil {
		t.Fatalf("new method failed: %v", err)
	}

	tests := []struct {
		name string
		attr eapaka.Attribute
	}{
		{name: "any", attr: &eapaka.AtAnyIdReq{}},
		{name: "fullauth", attr: &eapaka.AtFullauthIdReq{}},
	}

	for _, tc := range tests {
		req := &eapaka.Packet{
			Code:       eapaka.CodeRequest,
			Identifier: 4,
			Type:       eapaka.TypeAKA,
			Subtype:    eapaka.SubtypeIdentity,
			Attributes: []eapaka.Attribute{tc.attr},
		}
		raw, err := req.Marshal()
		if err != nil {
			t.Fatalf("%s marshal request failed: %v", tc.name, err)
		}
		eapReq, err := eap.Parse(raw)
		if err != nil {
			t.Fatalf("%s parse request failed: %v", tc.name, err)
		}

		sess := &eap.Session{OuterIdentity: "user@example"}
		resp, err := method.Handle(eapReq, sess)
		if err != nil {
			t.Fatalf("%s handle failed: %v", tc.name, err)
		}
		respRaw, err := resp.Encode()
		if err != nil {
			t.Fatalf("%s encode response failed: %v", tc.name, err)
		}
		akaResp, err := eapaka.Parse(respRaw)
		if err != nil {
			t.Fatalf("%s parse response failed: %v", tc.name, err)
		}
		found := false
		for _, attr := range akaResp.Attributes {
			if idAttr, ok := attr.(*eapaka.AtIdentity); ok {
				found = true
				if idAttr.Identity != "user@example" {
					t.Fatalf("%s unexpected identity %q", tc.name, idAttr.Identity)
				}
			}
		}
		if !found {
			t.Fatalf("%s expected AT_IDENTITY", tc.name)
		}
	}
}
