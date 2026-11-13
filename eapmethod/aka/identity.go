package aka

import (
	"fmt"

	"github.com/oyaguma3/eapaka_test/eap"

	eapaka "github.com/oyaguma3/go-eapaka"
)

func (m *Method) handleIdentity(req *eapaka.Packet, sess *eap.Session) (*eap.Packet, error) {
	m.s.identityRounds++
	m.s.phase = phaseIdentity
	if hasPermanentIDReq(req) {
		permanent, ok, err := m.selectPermanentIdentity(sess)
		if err != nil {
			return nil, err
		}
		if !ok {
			// RFC 4187 §4.1.5: 永続 ID を明かさないときは Client-Error を返す
			return m.clientError(req)
		}
		sess.InnerIdentity = permanent
		if m.outerIdentityUpdateOnPermanentReq {
			sess.OuterIdentity = permanent
		}
		resp := &eapaka.Packet{
			Code:       eapaka.CodeResponse,
			Identifier: req.Identifier,
			Type:       req.Type,
			Subtype:    eapaka.SubtypeIdentity,
			Attributes: []eapaka.Attribute{
				&eapaka.AtIdentity{Identity: permanent},
			},
		}
		return toEAPPacket(resp)
	}

	inner := sess.InnerIdentity
	if inner == "" {
		inner = sess.OuterIdentity
	}
	if inner == "" {
		return nil, fmt.Errorf("aka: inner identity is required")
	}
	resp := &eapaka.Packet{
		Code:       eapaka.CodeResponse,
		Identifier: req.Identifier,
		Type:       req.Type,
		Subtype:    eapaka.SubtypeIdentity,
		Attributes: []eapaka.Attribute{
			&eapaka.AtIdentity{Identity: inner},
		},
	}
	return toEAPPacket(resp)
}

func hasPermanentIDReq(req *eapaka.Packet) bool {
	for _, attr := range req.Attributes {
		if _, ok := attr.(*eapaka.AtPermanentIdReq); ok {
			return true
		}
	}
	return false
}

func (m *Method) selectPermanentIdentity(sess *eap.Session) (string, bool, error) {
	switch m.permanentIDPolicy {
	case "deny":
		return "", false, nil
	case "conservative":
		if isPermanentIdentity(sess.InnerIdentity, m.methodType) {
			return sess.InnerIdentity, true, nil
		}
		if isPermanentIdentity(sess.OuterIdentity, m.methodType) {
			return sess.OuterIdentity, true, nil
		}
		if m.permanentIdentityOverride != "" {
			return m.permanentIdentityOverride, true, nil
		}
		return "", false, nil
	case "always":
		if m.permanentIdentityOverride != "" {
			return m.permanentIdentityOverride, true, nil
		}
		return m.generatePermanentIdentity(), true, nil
	default:
		return "", false, fmt.Errorf("aka: unsupported permanent_id_policy %q", m.permanentIDPolicy)
	}
}

func (m *Method) generatePermanentIdentity() string {
	prefix := permanentPrefix(m.methodType)
	if m.realm == "" {
		return prefix + m.imsi
	}
	return prefix + m.imsi + "@" + m.realm
}

func permanentPrefix(methodType uint8) string {
	switch methodType {
	case eap.TypeAKA:
		return "0"
	case eap.TypeAKAPrime:
		return "6"
	default:
		return ""
	}
}

func isPermanentIdentity(identity string, methodType uint8) bool {
	if identity == "" {
		return false
	}
	return identity[:1] == permanentPrefix(methodType)
}

func normalizePermanentPolicy(policy string) string {
	if policy == "" {
		return "always"
	}
	return policy
}

func defaultOuterUpdate(value *bool) bool {
	if value == nil {
		return true
	}
	return *value
}
