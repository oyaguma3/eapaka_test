package eap

import (
	"encoding/binary"
	"fmt"
)

const (
	CodeRequest  uint8 = 1
	CodeResponse uint8 = 2
	CodeSuccess  uint8 = 3
	CodeFailure  uint8 = 4
)

const (
	TypeIdentity uint8 = 1
	TypeAKA      uint8 = 23
	TypeAKAPrime uint8 = 50
)

// Packet represents an EAP packet.
type Packet struct {
	Code       uint8
	Identifier uint8
	Type       uint8
	TypeData   []byte
}

// Parse decodes a raw EAP packet.
func Parse(b []byte) (Packet, error) {
	if len(b) < 4 {
		return Packet{}, fmt.Errorf("eap: packet too short")
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length < 4 {
		return Packet{}, fmt.Errorf("eap: invalid length %d", length)
	}
	if length > len(b) {
		return Packet{}, fmt.Errorf("eap: length %d exceeds buffer %d", length, len(b))
	}
	packet := Packet{
		Code:       b[0],
		Identifier: b[1],
	}
	payload := b[:length]
	if packet.Code == CodeRequest || packet.Code == CodeResponse {
		if len(payload) < 5 {
			return Packet{}, fmt.Errorf("eap: request/response missing type")
		}
		packet.Type = payload[4]
		if len(payload) > 5 {
			packet.TypeData = append([]byte(nil), payload[5:]...)
		}
	}
	return packet, nil
}

// Encode encodes the packet into raw bytes.
func (p Packet) Encode() ([]byte, error) {
	length := 4
	if p.Code == CodeRequest || p.Code == CodeResponse {
		length += 1 + len(p.TypeData)
	}
	b := make([]byte, length)
	b[0] = p.Code
	b[1] = p.Identifier
	binary.BigEndian.PutUint16(b[2:4], uint16(length))
	if p.Code == CodeRequest || p.Code == CodeResponse {
		b[4] = p.Type
		copy(b[5:], p.TypeData)
	}
	return b, nil
}

// IsRequest returns true if the packet is an EAP-Request.
func (p Packet) IsRequest() bool {
	return p.Code == CodeRequest
}

// IsResponse returns true if the packet is an EAP-Response.
func (p Packet) IsResponse() bool {
	return p.Code == CodeResponse
}
