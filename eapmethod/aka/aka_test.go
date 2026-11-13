package aka

import (
	"testing"

	"github.com/oyaguma3/eapaka_test/conformance"
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
	// RFC 4187 §4.1.5: 永続 ID を明かさないときは Client-Error(0) を返す
	if akaResp.Subtype != eapaka.SubtypeClientError {
		t.Fatalf("expected client error, got subtype %d", akaResp.Subtype)
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

func TestNetNameMatches(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"WLAN", "WLAN", true},
		{"5G:mnc010.mcc440.3gppnetwork.org", "5G", true},
		{"5G:mnc010.mcc440.3gppnetwork.org", "5G:mnc010.mcc440.3gppnetwork.org:extra", true},
		{"5G:mnc010.mcc440.3gppnetwork.org", "5G:mnc020.mcc440.3gppnetwork.org", false},
		{"WLAN", "wlan", false},
	}
	for _, tt := range tests {
		if got := netNameMatches(tt.a, tt.b); got != tt.want {
			t.Errorf("netNameMatches(%q, %q) = %t, want %t", tt.a, tt.b, got, tt.want)
		}
	}
}

// TestIdentityPrefixFollowsMethod は、AKA' の永続 ID のまま AKA を求められたとき、
// AKA の永続 ID（先頭 0）で答えることを確かめる。
func TestIdentityPrefixFollowsMethod(t *testing.T) {
	method, err := New(Options{MethodType: eap.TypeAKA, IMSI: "440100123456789", KI: make([]byte, 16), OPC: make([]byte, 16), AMF: []byte{0x80, 0}})
	if err != nil {
		t.Fatal(err)
	}
	req := &eapaka.Packet{Code: eapaka.CodeRequest, Identifier: 3, Type: eapaka.TypeAKA, Subtype: eapaka.SubtypeIdentity,
		Attributes: []eapaka.Attribute{&eapaka.AtAnyIdReq{}}}
	raw, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	eapReq, err := eap.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	sess := &eap.Session{OuterIdentity: "6440100123456789@example"}
	if _, err := method.Handle(eapReq, sess); err != nil {
		t.Fatal(err)
	}
	if sess.InnerIdentity != "0440100123456789@example" {
		t.Errorf("InnerIdentity = %q", sess.InnerIdentity)
	}
}

func TestCheckReserved(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want int // A-15 の件数
	}{
		{"clean", []byte{1, 1, 0, 16, 23, 5, 0, 0, 13, 1, 0, 0, 136, 1, 0x80, 0}, 0},
		{"header reserved", []byte{1, 1, 0, 12, 23, 5, 0, 1, 13, 1, 0, 0}, 1},
		{"AT_ANY_ID_REQ reserved", []byte{1, 1, 0, 12, 23, 5, 0, 0, 13, 1, 0, 9}, 1},
		{"AT_BIDDING reserved bits", []byte{1, 1, 0, 12, 23, 1, 0, 0, 136, 1, 0x81, 0}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := conformance.NewRecorder(conformance.DefaultPolicy())
			checkReserved(tt.raw, &eap.Session{Conformance: rec})
			if got := len(rec.Violations()); got != tt.want {
				t.Errorf("A-15 violations = %d, want %d: %+v", got, tt.want, rec.Violations())
			}
		})
	}
}
