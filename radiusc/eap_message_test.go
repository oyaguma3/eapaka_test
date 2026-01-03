package radiusc

import (
	"bytes"
	"testing"

	"layeh.com/radius"
)

func TestSplitJoinEAPMessage(t *testing.T) {
	payload := make([]byte, 600)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	chunks := SplitEAPMessage(payload)
	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks, got %d", len(chunks))
	}
	if len(chunks[0]) != 253 || len(chunks[1]) != 253 || len(chunks[2]) != 94 {
		t.Fatalf("unexpected chunk sizes: %d/%d/%d", len(chunks[0]), len(chunks[1]), len(chunks[2]))
	}
	joined := JoinEAPMessage(chunks)
	if !bytes.Equal(joined, payload) {
		t.Fatalf("join did not match original payload")
	}
}

func TestAddLookupEAPMessage(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	packet := radius.New(radius.CodeAccessRequest, []byte("secret"))
	if err := AddEAPMessage(packet, payload); err != nil {
		t.Fatalf("add failed: %v", err)
	}
	out, ok, err := LookupEAPMessage(packet)
	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	if !ok {
		t.Fatalf("expected eap message to be present")
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("expected %x, got %x", payload, out)
	}
}

func TestLookupEAPMessageMissing(t *testing.T) {
	packet := radius.New(radius.CodeAccessRequest, []byte("secret"))
	_, ok, err := LookupEAPMessage(packet)
	if err != nil {
		t.Fatalf("lookup failed: %v", err)
	}
	if ok {
		t.Fatalf("expected missing eap message")
	}
}
