package radiusc

import (
	"bytes"
	"testing"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func TestExtractMPPEKeys(t *testing.T) {
	send := []byte{0x10, 0x20, 0x30, 0x40}
	recv := []byte{0xaa, 0xbb, 0xcc}
	value := append(makeTLV(msMPPESendKeyType, send), makeTLV(msMPPERecvKeyType, recv)...)
	vsa, err := radius.NewVendorSpecific(vendorMicrosoftID, value)
	if err != nil {
		t.Fatalf("vendor specific create failed: %v", err)
	}
	packet := radius.New(radius.CodeAccessAccept, []byte("secret"))
	packet.Add(rfc2865.VendorSpecific_Type, vsa)

	keys, err := ExtractMPPEKeys(packet)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if !keys.SendKeyPresent || !bytes.Equal(keys.SendKey, send) {
		t.Fatalf("send key mismatch")
	}
	if !keys.RecvKeyPresent || !bytes.Equal(keys.RecvKey, recv) {
		t.Fatalf("recv key mismatch")
	}
}

func makeTLV(typ byte, value []byte) []byte {
	out := make([]byte, 2+len(value))
	out[0] = typ
	out[1] = byte(len(out))
	copy(out[2:], value)
	return out
}
