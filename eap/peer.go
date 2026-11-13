package eap

import (
	"fmt"

	"github.com/oyaguma3/eapaka_test/conformance"
)

// Session holds outer/inner identity data for the current EAP session.
type Session struct {
	OuterIdentity string
	InnerIdentity string

	// Conformance はサーバの RFC 違反を記録する。nil なら記録しない。
	Conformance *conformance.Recorder
	// Obs は期待値の判定とトレースに使う観測結果（設計書 §4.1）。
	Obs Observations
}

// MethodState は EAP メソッドの進み具合。
type MethodState int

const (
	MethodNotStarted MethodState = iota // メソッドの要求をまだ受けていない
	MethodInProgress                    // メソッドの途中
	MethodCompleted                     // ピアとしてメソッドを完了した（成功を受け取ってよい）
	MethodFailed                        // ピアが Authentication-Reject や Client-Error を送った
)

func (s MethodState) String() string {
	switch s {
	case MethodNotStarted:
		return "not_started"
	case MethodInProgress:
		return "in_progress"
	case MethodCompleted:
		return "completed"
	case MethodFailed:
		return "failed"
	default:
		return fmt.Sprintf("MethodState(%d)", int(s))
	}
}

// Observations は 1 回の EAP 交換で観測した結果。
type Observations struct {
	Method MethodState
	// Faults は注入した異常（X4）。"at/action" の形で記録する。
	Faults []string
}

// Method handles EAP method-specific requests.
type Method interface {
	Type() uint8
	Handle(req Packet, sess *Session) (*Packet, error)
}

// MethodMismatchError indicates the received method type differs from expected.
type MethodMismatchError struct {
	Expected uint8
	Received uint8
	Policy   MethodMismatchPolicy
}

func (e *MethodMismatchError) Error() string {
	return fmt.Sprintf("eap: method mismatch expected=%d received=%d policy=%s", e.Expected, e.Received, e.Policy)
}

// Peer handles EAP requests and dispatches to registered methods.
type Peer struct {
	Session        *Session
	Methods        map[uint8]Method
	MethodPolicy   MethodMismatchPolicy
	ExpectedMethod *uint8
	Warn           func(error)

	// method は最初に受けたメソッドの要求のタイプ（R-06 の検査用）。
	method uint8
}

// NewPeer creates a peer with the given session and methods.
func NewPeer(sess *Session, methods ...Method) *Peer {
	peer := &Peer{Session: sess, Methods: make(map[uint8]Method)}
	for _, method := range methods {
		if method != nil {
			peer.Methods[method.Type()] = method
		}
	}
	return peer
}

// Handle processes a server request and returns the response, if any.
func (p *Peer) Handle(req Packet) (*Packet, error) {
	if p == nil {
		return nil, fmt.Errorf("eap: peer is nil")
	}
	if req.Code == CodeSuccess || req.Code == CodeFailure {
		return nil, nil
	}
	if req.Code != CodeRequest {
		return nil, fmt.Errorf("eap: unsupported code %d", req.Code)
	}

	sess := p.Session
	if sess == nil {
		sess = &Session{}
	}

	if req.Type == TypeIdentity {
		return identityResponse(req.Identifier, sess.OuterIdentity)
	}

	method := p.Methods[req.Type]
	if method == nil {
		return nil, fmt.Errorf("eap: unsupported method %d", req.Type)
	}

	switch {
	case p.method == 0:
		p.method = req.Type
	case p.method != req.Type:
		sess.Conformance.Report("R-06", "EAP method switched from type %d to %d", p.method, req.Type)
	}

	if p.ExpectedMethod != nil && *p.ExpectedMethod != req.Type {
		mismatch := &MethodMismatchError{Expected: *p.ExpectedMethod, Received: req.Type, Policy: p.MethodPolicy}
		switch p.MethodPolicy {
		case MethodMismatchStrict:
			return nil, mismatch
		case MethodMismatchWarn:
			if p.Warn != nil {
				p.Warn(mismatch)
			}
		}
	}

	return method.Handle(req, sess)
}

func identityResponse(identifier uint8, identity string) (*Packet, error) {
	if identity == "" {
		return nil, fmt.Errorf("eap: outer identity is required")
	}
	return &Packet{
		Code:       CodeResponse,
		Identifier: identifier,
		Type:       TypeIdentity,
		TypeData:   []byte(identity),
	}, nil
}
