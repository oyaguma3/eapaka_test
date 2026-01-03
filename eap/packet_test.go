package eap

import (
	"bytes"
	"testing"
)

func TestPacketEncodeParse(t *testing.T) {
	pkt := Packet{
		Code:       CodeRequest,
		Identifier: 7,
		Type:       TypeIdentity,
		TypeData:   []byte("user@example"),
	}
	encoded, err := pkt.Encode()
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	parsed, err := Parse(encoded)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if parsed.Code != pkt.Code || parsed.Identifier != pkt.Identifier || parsed.Type != pkt.Type {
		t.Fatalf("header mismatch")
	}
	if !bytes.Equal(parsed.TypeData, pkt.TypeData) {
		t.Fatalf("type data mismatch")
	}
}

func TestParseInvalidLength(t *testing.T) {
	_, err := Parse([]byte{0x01, 0x01, 0x00, 0x02})
	if err == nil {
		t.Fatalf("expected error for invalid length")
	}
}
