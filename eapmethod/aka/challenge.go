package aka

import (
	"bytes"
	"fmt"

	"github.com/oyaguma3/eapaka_test/eap"

	eapaka "github.com/oyaguma3/go-eapaka"
	"github.com/wmnsk/milenage"
)

func (m *Method) handleChallenge(req *eapaka.Packet, sess *eap.Session) (*eap.Packet, error) {
	rand, autn, netName, err := m.extractChallengeParams(req)
	if err != nil {
		return nil, err
	}
	res, ck, ik, ak, err := m.computeVectors(rand)
	if err != nil {
		return nil, err
	}
	identity := sess.InnerIdentity
	if identity == "" {
		identity = sess.OuterIdentity
	}
	if identity == "" {
		return nil, fmt.Errorf("aka: inner identity is required")
	}

	kdfAttrs, err := selectKdfResponseAttrs(req)
	if err != nil {
		return nil, err
	}
	kAut, err := m.deriveKAut(identity, ck, ik, netName, autn)
	if err != nil {
		return nil, err
	}
	if err := verifyRequestMac(req, kAut); err != nil {
		return m.authenticationReject(req), nil
	}

	sqnBytes, amf, err := m.decodeAutn(autn, ak)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(amf, m.amfBytes()) {
		return nil, fmt.Errorf("aka: amf mismatch")
	}

	if ok, err := m.verifyMacA(rand, sqnBytes, amf, autn); err != nil {
		return nil, err
	} else if !ok {
		return m.authenticationReject(req), nil
	}

	if m.store != nil {
		accepted, err := m.acceptSQN(sqnBytes)
		if err != nil {
			return nil, err
		}
		if !accepted {
			auts, err := m.generateAUTS(rand)
			if err != nil {
				return nil, err
			}
			return m.synchronizationFailure(req, auts)
		}
	}

	attrs := []eapaka.Attribute{
		&eapaka.AtRes{Res: res},
	}
	if len(kdfAttrs) > 0 {
		attrs = append(attrs, kdfAttrs...)
	}
	attrs = append(attrs, &eapaka.AtMac{MAC: make([]byte, 16)})
	resp := &eapaka.Packet{
		Code:       eapaka.CodeResponse,
		Identifier: req.Identifier,
		Type:       req.Type,
		Subtype:    eapaka.SubtypeChallenge,
		Attributes: attrs,
	}
	if err := resp.CalculateAndSetMac(kAut); err != nil {
		return nil, err
	}
	m.s.phase = phaseChallenged
	return toEAPPacket(resp)
}

func (m *Method) extractChallengeParams(req *eapaka.Packet) ([]byte, []byte, string, error) {
	var rand []byte
	var autn []byte
	var netName string
	for _, attr := range req.Attributes {
		switch a := attr.(type) {
		case *eapaka.AtRand:
			rand = append([]byte(nil), a.Rand...)
		case *eapaka.AtAutn:
			autn = append([]byte(nil), a.Autn...)
		case *eapaka.AtKdfInput:
			netName = a.NetworkName
		}
	}
	if len(rand) != 16 {
		return nil, nil, "", fmt.Errorf("aka: AT_RAND is required")
	}
	if len(autn) != 16 {
		return nil, nil, "", fmt.Errorf("aka: AT_AUTN is required")
	}
	if req.Type == eapaka.TypeAKAPrime {
		if netName == "" {
			netName = m.netName
		}
		if netName == "" {
			return nil, nil, "", fmt.Errorf("aka: net_name is required for AKA'")
		}
	}
	return rand, autn, netName, nil
}

func selectKdfResponseAttrs(req *eapaka.Packet) ([]eapaka.Attribute, error) {
	if req.Type != eapaka.TypeAKAPrime {
		return nil, nil
	}
	offer := eapaka.KdfValuesFromAttributes(req.Attributes)
	if len(offer) == 0 {
		return nil, nil
	}
	if err := eapaka.ValidateKdfOffer(offer); err != nil {
		return nil, fmt.Errorf("aka: invalid AT_KDF offer: %w", err)
	}
	supported := eapaka.KDFAKAPrimeWithCKIK
	if offer[0] == supported {
		return nil, nil
	}
	for _, v := range offer {
		if v == supported {
			return []eapaka.Attribute{&eapaka.AtKdf{KDF: supported}}, nil
		}
	}
	return nil, fmt.Errorf("aka: unsupported AT_KDF offer")
}

func (m *Method) computeVectors(rand []byte) ([]byte, []byte, []byte, []byte, error) {
	mil := milenage.NewWithOPc(m.ki, m.opc, rand, 0, m.amf)
	return mil.F2345()
}

func (m *Method) deriveKAut(identity string, ck, ik []byte, netName string, autn []byte) ([]byte, error) {
	if m.methodType == eap.TypeAKA {
		keys := eapaka.DeriveKeysAKA(identity, ck, ik)
		return keys.K_aut, nil
	}
	ckPrime, ikPrime, err := eapaka.DeriveCKPrimeIKPrime(ck, ik, netName, autn)
	if err != nil {
		return nil, err
	}
	keys := eapaka.DeriveKeysAKAPrime(identity, ckPrime, ikPrime)
	return keys.K_aut, nil
}

func (m *Method) decodeAutn(autn, ak []byte) ([]byte, []byte, error) {
	if len(autn) != 16 {
		return nil, nil, fmt.Errorf("aka: invalid AUTN length")
	}
	if len(ak) != 6 {
		return nil, nil, fmt.Errorf("aka: invalid AK length")
	}
	sqn := make([]byte, 6)
	for i := 0; i < 6; i++ {
		sqn[i] = autn[i] ^ ak[i]
	}
	amf := append([]byte(nil), autn[6:8]...)
	return sqn, amf, nil
}

func (m *Method) verifyMacA(rand, sqn, amf, autn []byte) (bool, error) {
	mil := milenage.NewWithOPc(m.ki, m.opc, rand, 0, m.amf)
	copy(mil.SQN, sqn)
	copy(mil.AMF, amf)
	macA, err := mil.F1()
	if err != nil {
		return false, err
	}
	return bytes.Equal(macA, autn[8:16]), nil
}

func (m *Method) amfBytes() []byte {
	return []byte{byte(m.amf >> 8), byte(m.amf)}
}

func verifyRequestMac(req *eapaka.Packet, kAut []byte) error {
	_, hasMac := findMac(req)
	if !hasMac {
		return fmt.Errorf("aka: AT_MAC missing")
	}
	ok, err := req.VerifyMac(kAut)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("aka: request MAC mismatch")
	}
	return nil
}

func findMac(req *eapaka.Packet) (*eapaka.AtMac, bool) {
	for _, attr := range req.Attributes {
		if mac, ok := attr.(*eapaka.AtMac); ok {
			return mac, true
		}
	}
	return nil, false
}
