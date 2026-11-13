package aka

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/oyaguma3/eapaka_test/eap"
	"github.com/oyaguma3/eapaka_test/idstore"

	eapaka "github.com/oyaguma3/go-eapaka"
)

// handleIdentity は EAP-Request/AKA-Identity を処理する。要求の種類を記録して規則 A-01 を調べ、
// AT_CHECKCODE のために Request / Response を送受信したままの形で残す。
func (m *Method) handleIdentity(req *eapaka.Packet, raw []byte, sess *eap.Session) (*eap.Packet, error) {
	kind := identityRequestKind(req)
	sess.Obs.IdentityRequests = append(sess.Obs.IdentityRequests, kind)
	rec := sess.Conformance
	if m.s.counterTooSmallSent {
		rec.Report("A-11", "AKA-Identity (%s) after AT_COUNTER_TOO_SMALL", kind)
	}
	// 再認証 ID のまま答えない場合がある。AT_FULLAUTH_ID_REQ（RFC 4187 §4.1.5）と、別のメソッドの
	// 再認証 ID（RFC 9048 §7: メソッドをまたいで再認証しない）。仮名があれば仮名、なければ永続 ID で答える
	if m.reauthIdentity != "" && kind != "permanent" {
		cur := sess.InnerIdentity
		if cur == "" {
			cur = sess.OuterIdentity
		}
		if cur == m.reauthIdentity && (kind == "fullauth" || m.reauthCtx == nil) {
			sess.InnerIdentity = m.fullauthIdentity(sess)
			sess.Warnf("AT_%s_ID_REQ: answering with a full-authentication identity instead of the re-authentication identity",
				strings.ToUpper(kind))
		}
	}
	switch {
	case m.s.permanentRequested:
		rec.Report("A-01", "AKA-Identity (%s) after AT_PERMANENT_ID_REQ", kind)
	case m.s.identityRounds >= 3:
		rec.Report("A-01", "more than 3 AKA-Identity rounds")
	case kind == "any" && m.s.identityRounds > 0:
		rec.Report("A-01", "AT_ANY_ID_REQ in AKA-Identity round %d (only the first round may use it)", m.s.identityRounds+1)
	}
	if kind == "permanent" {
		m.s.permanentRequested = true
	}
	resp, err := m.identityResponse(req, sess)
	if err == nil && resp != nil && len(resp.TypeData) > 0 && resp.TypeData[0] == eapaka.SubtypeIdentity {
		if b, encErr := resp.Encode(); encErr == nil {
			m.s.identityMsgs = append(m.s.identityMsgs, bytes.Clone(raw), b)
		}
	}
	return resp, err
}

// identityRequestKind は AKA-Identity の要求の種類を返す。
func identityRequestKind(req *eapaka.Packet) string {
	for _, a := range req.Attributes {
		switch a.(type) {
		case *eapaka.AtPermanentIdReq:
			return "permanent"
		case *eapaka.AtFullauthIdReq:
			return "fullauth"
		case *eapaka.AtAnyIdReq:
			return "any"
		}
	}
	return "none"
}

func (m *Method) identityResponse(req *eapaka.Packet, sess *eap.Session) (*eap.Packet, error) {
	m.s.identityRounds++
	m.s.phase = phaseIdentity
	if resp, ok, err := m.replaceByFault(m.faultAt(FaultAtIdentityResponse, sess), req); ok {
		return resp, err
	}
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
	// Nak などで別のメソッドに切り替わったときは、そのメソッドの永続 ID の先頭文字
	// （AKA は 0、AKA' は 6）に合わせる。鍵の導出にもこの ID を使う
	if other := permanentPrefix(otherMethod(m.methodType)); other != "" && strings.HasPrefix(inner, other) {
		adjusted := permanentPrefix(m.methodType) + inner[1:]
		sess.Warnf("identity prefix changed from %q to %q for EAP type %d", other, permanentPrefix(m.methodType), m.methodType)
		inner = adjusted
		sess.InnerIdentity = adjusted
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

// otherMethod は、EAP-AKA と EAP-AKA' のうち、もう一方のタイプを返す。
func otherMethod(methodType uint8) uint8 {
	if methodType == eap.TypeAKA {
		return eap.TypeAKAPrime
	}
	return eap.TypeAKA
}

// fullauthIdentity は、フル認証に使う ID を返す。保存済みの仮名があれば仮名＋レルム、なければ永続 ID。
func (m *Method) fullauthIdentity(sess *eap.Session) string {
	if m.idstore != nil {
		e, err := m.idstore.Get(m.imsi, idstore.MethodFor(m.methodType))
		if err != nil {
			sess.Warnf("identity store: %v", err)
		} else if e.Pseudonym != nil {
			if m.realm == "" {
				return e.Pseudonym.Username
			}
			return e.Pseudonym.Username + "@" + m.realm
		}
	}
	return m.generatePermanentIdentity()
}
