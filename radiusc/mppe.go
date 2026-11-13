package radiusc

import (
	"fmt"

	eapaka "github.com/oyaguma3/go-eapaka"

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

// DecryptMPPEKeys は MS-MPPE-Send-Key と MS-MPPE-Recv-Key を復号する（RFC 2548 §2.4.2-3）。
// reqAuth は、応答に対応する Access-Request の Request Authenticator。
func DecryptMPPEKeys(keys MPPEKeys, secret []byte, reqAuth [16]byte) (send, recv []byte, err error) {
	if !keys.SendKeyPresent || !keys.RecvKeyPresent {
		return nil, nil, fmt.Errorf("radiusc: MS-MPPE-Send-Key or MS-MPPE-Recv-Key is missing")
	}
	if send, err = eapaka.DecryptMPPEKey(keys.SendKey, secret, reqAuth[:]); err != nil {
		return nil, nil, fmt.Errorf("radiusc: decrypt MS-MPPE-Send-Key: %w", err)
	}
	if recv, err = eapaka.DecryptMPPEKey(keys.RecvKey, secret, reqAuth[:]); err != nil {
		return nil, nil, fmt.Errorf("radiusc: decrypt MS-MPPE-Recv-Key: %w", err)
	}
	return send, recv, nil
}
