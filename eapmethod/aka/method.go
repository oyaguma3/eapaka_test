package aka

import (
	"fmt"

	"github.com/oyaguma3/eapaka_test/eap"
	"github.com/oyaguma3/eapaka_test/sqnstore"

	eapaka "github.com/oyaguma3/go-eapaka"
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

	s akaSession
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

	resp, err := m.dispatch(akaReq, session)
	session.Obs.Method = m.s.phase.methodState()
	return resp, err
}

func (m *Method) dispatch(akaReq *eapaka.Packet, session *eap.Session) (*eap.Packet, error) {
	switch akaReq.Subtype {
	case eapaka.SubtypeIdentity:
		return m.handleIdentity(akaReq, session)
	case eapaka.SubtypeChallenge:
		return m.handleChallenge(akaReq, session)
	default:
		return nil, fmt.Errorf("aka: unsupported subtype %d", akaReq.Subtype)
	}
}
