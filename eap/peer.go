package eap

import "fmt"

// Session holds outer/inner identity data for the current EAP session.
type Session struct {
	OuterIdentity string
	InnerIdentity string
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
