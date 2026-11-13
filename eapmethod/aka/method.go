package aka

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"slices"

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

	// EmptyKdfInput は空の AT_KDF_INPUT の扱い。"reject"（既定、RFC 9048 §3.1）か
	// "fallback"（NetName で補う互換モード）。
	EmptyKdfInput string
	// NetNameCheck は AT_KDF_INPUT と NetName の照合。"off"（既定）、"warn"、"reject"。
	NetNameCheck string

	// Faults は注入する異常（X4）。
	Faults []Fault
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

	emptyKdfInput string
	netNameCheck  string
	faults        []Fault

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

		emptyKdfInput: cmp.Or(opts.EmptyKdfInput, "reject"),
		netNameCheck:  cmp.Or(opts.NetNameCheck, "off"),
		faults:        slices.Clone(opts.Faults),
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
	session := sess
	if session == nil {
		session = &eap.Session{}
	}
	resp, err := m.handle(req, raw, session)
	session.Obs.Method = m.s.phase.methodState()
	return resp, err
}

func (m *Method) handle(req eap.Packet, raw []byte, sess *eap.Session) (*eap.Packet, error) {
	if req.Type != m.methodType {
		return nil, fmt.Errorf("aka: method type mismatch %d", req.Type)
	}
	akaReq, err := eapaka.Parse(raw)
	if errors.Is(err, eapaka.ErrEmptyKdfInput) && req.Type == eap.TypeAKAPrime {
		// RFC 9048 §3.1: 空の AT_KDF_INPUT では認証を続けない
		sess.Conformance.Report("A-13", "AT_KDF_INPUT has an empty network name")
		m.s.emptyKdfInputReported = true
		if m.emptyKdfInput != "fallback" || m.netName == "" {
			return m.authenticationReject(&eapaka.Packet{Identifier: req.Identifier, Type: req.Type}), nil
		}
		// 互換モード: 空の AT_KDF_INPUT を読み飛ばして解析し、設定のネットワーク名で補う。
		// AT_MAC は受信したバイト列（raw）のまま検証する
		akaReq, err = eapaka.Parse(maskAttribute(raw, eapaka.AT_KDF_INPUT))
	}
	if err != nil {
		if errors.Is(err, eapaka.ErrMalformedPacket) || errors.Is(err, eapaka.ErrMalformedAttribute) {
			// RFC 4187 §6.3.1: 解析できないパケットには Client-Error を返す
			sess.Conformance.Report("A-16", "malformed EAP-AKA request: %v", err)
			return m.clientErrorFor(req)
		}
		return nil, err
	}
	for _, attr := range akaReq.Attributes {
		if g, ok := attr.(*eapaka.GenericAttribute); ok && !eapaka.IsSkippable(g.AttrType) {
			// RFC 4187 §8.1: 未知のスキップ不可属性があればパケットを処理しない
			sess.Conformance.Report("A-16", "unknown non-skippable attribute %d in subtype %d", g.AttrType, akaReq.Subtype)
			return m.clientError(akaReq)
		}
	}

	switch akaReq.Subtype {
	case eapaka.SubtypeIdentity:
		return m.handleIdentity(akaReq, sess)
	case eapaka.SubtypeChallenge:
		return m.handleChallenge(akaReq, raw, sess)
	case eapaka.SubtypeNotification, eapaka.SubtypeReauthentication:
		// ツールがまだ対応していない（Phase 3・5 で対応する）
		return nil, fmt.Errorf("aka: unsupported subtype %d", akaReq.Subtype)
	default:
		// 未定義の Subtype や、ピアからしか送らない Subtype（Authentication-Reject など）
		sess.Conformance.Report("A-16", "unexpected subtype %d in EAP-Request", akaReq.Subtype)
		return m.clientError(akaReq)
	}
}

// maskAttribute は、raw の中の型 t の属性を、未割り当てのスキップ可能な型（255）に
// 書き換えたコピーを返す。解析で読み飛ばさせるためだけに使う。
func maskAttribute(raw []byte, t eapaka.AttributeType) []byte {
	out := bytes.Clone(raw)
	for off := 8; off+2 <= len(out); {
		length := int(out[off+1]) * 4
		if length == 0 {
			break
		}
		if eapaka.AttributeType(out[off]) == t {
			out[off] = 255
		}
		off += length
	}
	return out
}
