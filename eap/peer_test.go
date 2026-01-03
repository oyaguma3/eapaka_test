package eap

import "testing"

type stubMethod struct {
	typeID uint8
	called bool
}

func (s *stubMethod) Type() uint8 {
	return s.typeID
}

func (s *stubMethod) Handle(req Packet, sess *Session) (*Packet, error) {
	s.called = true
	return &Packet{Code: CodeResponse, Identifier: req.Identifier, Type: s.typeID}, nil
}

func TestHandleIdentity(t *testing.T) {
	peer := NewPeer(&Session{OuterIdentity: "user@example"})
	resp, err := peer.Handle(Packet{Code: CodeRequest, Identifier: 9, Type: TypeIdentity})
	if err != nil {
		t.Fatalf("handle failed: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected response")
	}
	if resp.Code != CodeResponse || resp.Type != TypeIdentity || string(resp.TypeData) != "user@example" {
		t.Fatalf("unexpected identity response")
	}
}

func TestHandleMethodMismatchStrict(t *testing.T) {
	method := &stubMethod{typeID: TypeAKA}
	peer := NewPeer(&Session{OuterIdentity: "user"}, method)
	expected := TypeAKAPrime
	peer.ExpectedMethod = &expected
	peer.MethodPolicy = MethodMismatchStrict

	_, err := peer.Handle(Packet{Code: CodeRequest, Identifier: 1, Type: TypeAKA})
	if err == nil {
		t.Fatalf("expected mismatch error")
	}
	if method.called {
		t.Fatalf("method should not be called under strict policy")
	}
}

func TestHandleMethodMismatchWarn(t *testing.T) {
	method := &stubMethod{typeID: TypeAKA}
	peer := NewPeer(&Session{OuterIdentity: "user"}, method)
	expected := TypeAKAPrime
	peer.ExpectedMethod = &expected
	peer.MethodPolicy = MethodMismatchWarn
	var warned bool
	peer.Warn = func(error) { warned = true }

	_, err := peer.Handle(Packet{Code: CodeRequest, Identifier: 1, Type: TypeAKA})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !warned {
		t.Fatalf("expected warning callback")
	}
	if !method.called {
		t.Fatalf("expected method to be called")
	}
}

func TestHandleUnsupportedMethod(t *testing.T) {
	peer := NewPeer(&Session{OuterIdentity: "user"})
	_, err := peer.Handle(Packet{Code: CodeRequest, Identifier: 1, Type: TypeAKA})
	if err == nil {
		t.Fatalf("expected unsupported method error")
	}
}
