package aka

import (
	"bytes"
	"fmt"

	"github.com/oyaguma3/eapaka_test/eap"
	"github.com/oyaguma3/eapaka_test/sqnstore"

	eapaka "github.com/oyaguma3/go-eapaka"
	"github.com/wmnsk/milenage"
)

// Options configures the EAP-AKA/AKA' method.
type Options struct {
	MethodType uint8
	IMSI       string
	KI         []byte
	OPC        []byte
	AMF        []byte
	NetName    string
	Realm      string
	InitialSQN uint64
	SQNStore   sqnstore.Store

	PermanentIDPolicy                 string
	PermanentIdentityOverride         string
	OuterIdentityUpdateOnPermanentReq *bool
}

// Method implements the EAP method for AKA and AKA'.
type Method struct {
	methodType uint8
	imsi       string
	ki         []byte
	opc        []byte
	amf        uint16
	netName    string
	realm      string
	initialSQN uint64
	store      sqnstore.Store

	permanentIDPolicy                 string
	permanentIdentityOverride         string
	outerIdentityUpdateOnPermanentReq bool
}

// New creates a new AKA/AKA' method handler.
func New(opts Options) (*Method, error) {
	if opts.MethodType != eap.TypeAKA && opts.MethodType != eap.TypeAKAPrime {
		return nil, fmt.Errorf("aka: unsupported method type %d", opts.MethodType)
	}
	if len(opts.KI) != 16 {
		return nil, fmt.Errorf("aka: KI must be 16 bytes")
	}
	if len(opts.OPC) != 16 {
		return nil, fmt.Errorf("aka: OPC must be 16 bytes")
	}
	if len(opts.AMF) != 2 {
		return nil, fmt.Errorf("aka: AMF must be 2 bytes")
	}
	if opts.IMSI == "" {
		return nil, fmt.Errorf("aka: IMSI is required")
	}
	amf := uint16(opts.AMF[0])<<8 | uint16(opts.AMF[1])
	method := &Method{
		methodType: opts.MethodType,
		imsi:       opts.IMSI,
		ki:         append([]byte(nil), opts.KI...),
		opc:        append([]byte(nil), opts.OPC...),
		amf:        amf,
		netName:    opts.NetName,
		realm:      opts.Realm,
		initialSQN: opts.InitialSQN,
		store:      opts.SQNStore,

		permanentIDPolicy:                 normalizePermanentPolicy(opts.PermanentIDPolicy),
		permanentIdentityOverride:         opts.PermanentIdentityOverride,
		outerIdentityUpdateOnPermanentReq: defaultOuterUpdate(opts.OuterIdentityUpdateOnPermanentReq),
	}
	return method, nil
}

// Type returns the EAP method type handled by this method.
func (m *Method) Type() uint8 {
	return m.methodType
}

// Handle processes EAP-Request/AKA(-') messages.
func (m *Method) Handle(req eap.Packet, sess *eap.Session) (*eap.Packet, error) {
	if m == nil {
		return nil, fmt.Errorf("aka: method is nil")
	}
	raw, err := req.Encode()
	if err != nil {
		return nil, err
	}
	akaReq, err := eapaka.Parse(raw)
	if err != nil {
		return nil, err
	}
	if akaReq.Type != m.methodType {
		return nil, fmt.Errorf("aka: method type mismatch %d", akaReq.Type)
	}

	session := sess
	if session == nil {
		session = &eap.Session{}
	}

	switch akaReq.Subtype {
	case eapaka.SubtypeIdentity:
		return m.handleIdentity(akaReq, session)
	case eapaka.SubtypeChallenge:
		return m.handleChallenge(akaReq, session)
	default:
		return nil, fmt.Errorf("aka: unsupported subtype %d", akaReq.Subtype)
	}
}

func (m *Method) handleIdentity(req *eapaka.Packet, sess *eap.Session) (*eap.Packet, error) {
	if hasPermanentIDReq(req) {
		permanent, ok, err := m.selectPermanentIdentity(sess)
		if err != nil {
			return nil, err
		}
		if !ok {
			return m.authenticationReject(req), nil
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

	kAut, err := m.deriveKAut(identity, ck, ik, netName)
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

	resp := &eapaka.Packet{
		Code:       eapaka.CodeResponse,
		Identifier: req.Identifier,
		Type:       req.Type,
		Subtype:    eapaka.SubtypeChallenge,
		Attributes: []eapaka.Attribute{
			&eapaka.AtRes{Res: res},
			&eapaka.AtMac{MAC: make([]byte, 16)},
		},
	}
	if err := resp.CalculateAndSetMac(kAut); err != nil {
		return nil, err
	}
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

func (m *Method) computeVectors(rand []byte) ([]byte, []byte, []byte, []byte, error) {
	mil := milenage.NewWithOPc(m.ki, m.opc, rand, 0, m.amf)
	return mil.F2345()
}

func (m *Method) deriveKAut(identity string, ck, ik []byte, netName string) ([]byte, error) {
	if m.methodType == eap.TypeAKA {
		keys := eapaka.DeriveKeysAKA(identity, ck, ik)
		return keys.K_aut, nil
	}
	ckPrime, ikPrime := eapaka.DeriveCKPrimeIKPrime(ck, ik, netName)
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

func (m *Method) acceptSQN(sqnBytes []byte) (bool, error) {
	sqnValue, err := sqnBytesToUint64(sqnBytes)
	if err != nil {
		return false, err
	}
	state, ok, err := m.store.Load(m.imsi)
	if err != nil {
		return false, err
	}
	if !ok {
		state = initialState(m.initialSQN)
	}
	accepted, err := state.AcceptSQN(sqnValue)
	if err != nil {
		return false, err
	}
	if accepted {
		if err := m.store.Save(m.imsi, state); err != nil {
			return false, err
		}
	}
	return accepted, nil
}

func (m *Method) generateAUTS(rand []byte) ([]byte, error) {
	state, ok, err := m.store.Load(m.imsi)
	if err != nil {
		return nil, err
	}
	if !ok {
		state = initialState(m.initialSQN)
	}
	mil := milenage.NewWithOPc(m.ki, m.opc, rand, state.SQNMS, 0)
	return mil.GenerateAUTS()
}

func (m *Method) synchronizationFailure(req *eapaka.Packet, auts []byte) (*eap.Packet, error) {
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

func (m *Method) amfBytes() []byte {
	return []byte{byte(m.amf >> 8), byte(m.amf)}
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

func sqnBytesToUint64(b []byte) (uint64, error) {
	if len(b) != 6 {
		return 0, fmt.Errorf("aka: invalid SQN length")
	}
	var v uint64
	for i := 0; i < 6; i++ {
		v = (v << 8) | uint64(b[i])
	}
	return v, nil
}

func initialState(sqn uint64) sqnstore.SubscriberState {
	var state sqnstore.SubscriberState
	seq, ind, err := sqnstore.SplitSQN(sqn)
	if err == nil {
		state.SeqMS[ind] = seq
		state.SQNMS = sqn
	}
	return state
}
