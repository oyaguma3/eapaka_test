package sqnstore

import "fmt"

// MemoryStore keeps SQN state in memory for a single process.
type MemoryStore struct {
	data map[string]SubscriberState
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{data: make(map[string]SubscriberState)}
}

func (m *MemoryStore) Load(imsi string) (SubscriberState, bool, error) {
	if imsi == "" {
		return SubscriberState{}, false, fmt.Errorf("sqnstore: imsi is required")
	}
	if m == nil {
		return SubscriberState{}, false, fmt.Errorf("sqnstore: store is nil")
	}
	state, ok := m.data[imsi]
	return state, ok, nil
}

func (m *MemoryStore) Save(imsi string, state SubscriberState) error {
	if imsi == "" {
		return fmt.Errorf("sqnstore: imsi is required")
	}
	if m == nil {
		return fmt.Errorf("sqnstore: store is nil")
	}
	if m.data == nil {
		m.data = make(map[string]SubscriberState)
	}
	m.data[imsi] = state
	return nil
}

func (m *MemoryStore) Reset(imsi string) error {
	if imsi == "" {
		return fmt.Errorf("sqnstore: imsi is required")
	}
	if m == nil {
		return fmt.Errorf("sqnstore: store is nil")
	}
	if m.data == nil {
		return nil
	}
	delete(m.data, imsi)
	return nil
}
