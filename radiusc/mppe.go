package radiusc

import (
	"fmt"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

const (
	vendorMicrosoftID = 311
	msMPPERecvKeyType = 17
	msMPPESendKeyType = 16
)

// MPPEKeys holds raw (encrypted) MS-MPPE key attributes.
type MPPEKeys struct {
	SendKey        []byte
	RecvKey        []byte
	SendKeyPresent bool
	RecvKeyPresent bool
}

// ExtractMPPEKeys extracts raw MS-MPPE send/recv key attributes from the packet.
func ExtractMPPEKeys(p *radius.Packet) (MPPEKeys, error) {
	if p == nil {
		return MPPEKeys{}, fmt.Errorf("radiusc: packet is nil")
	}
	var keys MPPEKeys
	for _, avp := range p.Attributes {
		if avp.Type != rfc2865.VendorSpecific_Type {
			continue
		}
		vendorID, value, err := radius.VendorSpecific(avp.Attribute)
		if err != nil {
			return MPPEKeys{}, err
		}
		if vendorID != vendorMicrosoftID {
			continue
		}
		tlvs, err := parseVendorTLVs(value)
		if err != nil {
			return MPPEKeys{}, err
		}
		for _, tlv := range tlvs {
			switch tlv.typ {
			case msMPPESendKeyType:
				keys.SendKey = append([]byte(nil), tlv.value...)
				keys.SendKeyPresent = true
			case msMPPERecvKeyType:
				keys.RecvKey = append([]byte(nil), tlv.value...)
				keys.RecvKeyPresent = true
			}
		}
	}
	return keys, nil
}

type vendorTLV struct {
	typ   byte
	value []byte
}

func parseVendorTLVs(b []byte) ([]vendorTLV, error) {
	var out []vendorTLV
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, fmt.Errorf("radiusc: vendor tlv too short")
		}
		length := int(b[1])
		if length < 2 || length > len(b) {
			return nil, fmt.Errorf("radiusc: invalid vendor tlv length")
		}
		value := make([]byte, length-2)
		copy(value, b[2:length])
		out = append(out, vendorTLV{typ: b[0], value: value})
		b = b[length:]
	}
	return out, nil
}
