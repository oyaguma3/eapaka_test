package eap

import (
	"bytes"
	"testing"
)

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

// TestHandleUnsupportedMethod は、対応していないメソッドに Nak(0) で応答することを確かめる（RFC 3748 §5.3.1）。
func TestHandleUnsupportedMethod(t *testing.T) {
	peer := NewPeer(&Session{OuterIdentity: "user"})
	resp, err := peer.Handle(Packet{Code: CodeRequest, Identifier: 1, Type: TypeAKA})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Type != TypeNak || !bytes.Equal(resp.TypeData, []byte{0}) || resp.Identifier != 1 {
		t.Fatalf("response = %+v, want Nak [0]", resp)
	}
}

func TestNak(t *testing.T) {
	tests := []struct {
		name       string
		preference []uint8
		nakOn      []uint8
		propose    []uint8
		offered    uint8
		wantNak    []byte // nil なら Nak しない
	}{
		{name: "supported method is accepted", offered: TypeAKA},
		{name: "method outside the preference", preference: []uint8{TypeAKAPrime}, offered: TypeAKA, wantNak: []byte{TypeAKAPrime}},
		{name: "unknown method gets the preference", offered: 4, wantNak: []byte{TypeAKAPrime, TypeAKA}},
		{name: "forced Nak", nakOn: []uint8{TypeAKAPrime}, propose: []uint8{TypeAKA}, offered: TypeAKAPrime, wantNak: []byte{TypeAKA}},
		{name: "forced Nak without proposal", nakOn: []uint8{TypeAKA}, offered: TypeAKA, wantNak: []byte{0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess := &Session{OuterIdentity: "user"}
			peer := NewPeer(sess, &stubMethod{typeID: TypeAKA}, &stubMethod{typeID: TypeAKAPrime})
			peer.MethodPreference, peer.NakOn, peer.NakPropose = tt.preference, tt.nakOn, tt.propose
			resp, err := peer.Handle(Packet{Code: CodeRequest, Identifier: 7, Type: tt.offered})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantNak == nil {
				if resp.Type == TypeNak {
					t.Fatalf("unexpected Nak %v", resp.TypeData)
				}
				return
			}
			if resp.Type != TypeNak || !bytes.Equal(resp.TypeData, tt.wantNak) {
				t.Fatalf("response type %d data %v, want Nak %v", resp.Type, resp.TypeData, tt.wantNak)
			}
			if len(sess.Obs.Naks) != 1 || sess.Obs.Naks[0].Offered != tt.offered {
				t.Errorf("Obs.Naks = %+v", sess.Obs.Naks)
			}
		})
	}
}

// TestNoNakAfterMethodStarted は、メソッドに応答した後は Nak を送らないことを確かめる。
func TestNoNakAfterMethodStarted(t *testing.T) {
	peer := NewPeer(&Session{OuterIdentity: "user"}, &stubMethod{typeID: TypeAKA})
	if _, err := peer.Handle(Packet{Code: CodeRequest, Identifier: 1, Type: TypeAKA}); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Handle(Packet{Code: CodeRequest, Identifier: 2, Type: 4}); err == nil {
		t.Fatal("expected an error instead of a Nak after the method started")
	}
}
