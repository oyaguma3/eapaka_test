package aka

import (
	"github.com/oyaguma3/eapaka_test/eap"

	eapaka "github.com/oyaguma3/go-eapaka"
)

func (m *Method) synchronizationFailure(req *eapaka.Packet, auts []byte) (*eap.Packet, error) {
	m.s.phase = phaseSyncFailure
	resp := &eapaka.Packet{
		Code:       eapaka.CodeResponse,
		Identifier: req.Identifier,
		Type:       req.Type,
		Subtype:    eapaka.SubtypeSynchronizationFailure,
		Attributes: []eapaka.Attribute{
			&eapaka.AtAuts{Auts: auts},
		},
	}
	return toEAPPacket(resp)
}

func (m *Method) authenticationReject(req *eapaka.Packet) *eap.Packet {
	m.s.phase = phaseFailed
	resp := &eapaka.Packet{
		Code:       eapaka.CodeResponse,
		Identifier: req.Identifier,
		Type:       req.Type,
		Subtype:    eapaka.SubtypeAuthenticationReject,
	}
	packet, err := toEAPPacket(resp)
	if err != nil {
		return nil
	}
	return packet
}

func toEAPPacket(pkt *eapaka.Packet) (*eap.Packet, error) {
	raw, err := pkt.Marshal()
	if err != nil {
		return nil, err
	}
	eapPkt, err := eap.Parse(raw)
	if err != nil {
		return nil, err
	}
	return &eapPkt, nil
}

// clientError は AT_CLIENT_ERROR_CODE が 0（unable to process packet）の
// EAP-Response/AKA-Client-Error を返す（RFC 4187 §6.3.1、§10.20）。
func (m *Method) clientError(req *eapaka.Packet) (*eap.Packet, error) {
	m.s.phase = phaseFailed
	return toEAPPacket(&eapaka.Packet{
		Code:       eapaka.CodeResponse,
		Identifier: req.Identifier,
		Type:       req.Type,
		Subtype:    eapaka.SubtypeClientError,
		Attributes: []eapaka.Attribute{&eapaka.AtClientErrorCode{Code: 0}},
	})
}

// clientErrorFor は、EAP-AKA として解析できなかった要求に Client-Error を返す。
func (m *Method) clientErrorFor(req eap.Packet) (*eap.Packet, error) {
	return m.clientError(&eapaka.Packet{Identifier: req.Identifier, Type: req.Type})
}
