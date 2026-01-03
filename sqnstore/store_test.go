package sqnstore

import "testing"

func TestSubscriberStateAcceptSQN(t *testing.T) {
	var state SubscriberState
	accepted, err := state.AcceptSQN(0x000000000021) // seq=1, ind=1
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !accepted {
		t.Fatalf("expected accepted SQN")
	}
	if state.SeqMS[1] != 1 {
		t.Fatalf("expected seqms[1]=1, got %d", state.SeqMS[1])
	}
	if state.SQNMS != 0x21 {
		t.Fatalf("expected sqnms=0x21, got 0x%x", state.SQNMS)
	}

	accepted, err = state.AcceptSQN(0x000000000021)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if accepted {
		t.Fatalf("expected duplicate SQN to be rejected")
	}
}

func TestSQNHexRoundTrip(t *testing.T) {
	val := uint64(0x000000abcdef)
	encoded, err := FormatSQNHex(val)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	parsed, err := ParseSQNHex(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed != val {
		t.Fatalf("expected %x, got %x", val, parsed)
	}
}
