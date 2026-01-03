package radiusc

import (
	"fmt"

	"layeh.com/radius"
	"layeh.com/radius/rfc2869"
)

const maxEAPMessageChunk = 253

// SplitEAPMessage splits payload into RADIUS EAP-Message chunks.
func SplitEAPMessage(payload []byte) [][]byte {
	if len(payload) == 0 {
		return nil
	}
	chunks := make([][]byte, 0, (len(payload)/maxEAPMessageChunk)+1)
	for len(payload) > 0 {
		n := len(payload)
		if n > maxEAPMessageChunk {
			n = maxEAPMessageChunk
		}
		chunk := make([]byte, n)
		copy(chunk, payload[:n])
		chunks = append(chunks, chunk)
		payload = payload[n:]
	}
	return chunks
}

// JoinEAPMessage concatenates chunks into a single payload.
func JoinEAPMessage(chunks [][]byte) []byte {
	if len(chunks) == 0 {
		return nil
	}
	var total int
	for _, chunk := range chunks {
		total += len(chunk)
	}
	out := make([]byte, 0, total)
	for _, chunk := range chunks {
		out = append(out, chunk...)
	}
	return out
}

// AddEAPMessage appends EAP-Message attributes to the packet.
func AddEAPMessage(p *radius.Packet, payload []byte) error {
	if p == nil {
		return fmt.Errorf("radiusc: packet is nil")
	}
	if len(payload) == 0 {
		return fmt.Errorf("radiusc: eap message is empty")
	}
	p.Attributes.Del(rfc2869.EAPMessage_Type)
	for _, chunk := range SplitEAPMessage(payload) {
		attr, err := radius.NewBytes(chunk)
		if err != nil {
			return err
		}
		p.Add(rfc2869.EAPMessage_Type, attr)
	}
	return nil
}

// LookupEAPMessage concatenates EAP-Message attributes from the packet.
func LookupEAPMessage(p *radius.Packet) ([]byte, bool, error) {
	if p == nil {
		return nil, false, fmt.Errorf("radiusc: packet is nil")
	}
	var out []byte
	found := false
	for _, avp := range p.Attributes {
		if avp.Type != rfc2869.EAPMessage_Type {
			continue
		}
		out = append(out, avp.Attribute...)
		found = true
	}
	if !found {
		return nil, false, nil
	}
	return out, true, nil
}
