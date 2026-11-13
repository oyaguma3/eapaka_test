package aka

import (
	"fmt"

	"github.com/oyaguma3/eapaka_test/sqnstore"
	"github.com/wmnsk/milenage"
)

// checkSQN は SQN の鮮度を確かめ、受け入れた後の状態を返す（保存はしない）。
// AT_MAC と AT_BIDDING を確かめた後に saveSQN で保存する（設計書 §5.1）。
func (m *Method) checkSQN(sqnBytes []byte) (sqnstore.SubscriberState, bool, error) {
	sqnValue, err := sqnBytesToUint64(sqnBytes)
	if err != nil {
		return sqnstore.SubscriberState{}, false, err
	}
	state, ok, err := m.store.Load(m.imsi)
	if err != nil {
		return sqnstore.SubscriberState{}, false, err
	}
	if !ok {
		state = initialState(m.initialSQN)
	}
	accepted, err := state.AcceptSQN(sqnValue)
	if err != nil {
		return sqnstore.SubscriberState{}, false, err
	}
	return state, accepted, nil
}

// saveSQN は checkSQN で受け入れた状態を保存する。
func (m *Method) saveSQN(state sqnstore.SubscriberState) error {
	return m.store.Save(m.imsi, state)
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
