package sqnstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const storeVersion = 1

type Store interface {
	Load(imsi string) (SubscriberState, bool, error)
	Save(imsi string, state SubscriberState) error
	Reset(imsi string) error
}

type FileStore struct {
	Path string
	Now  func() time.Time
}

func (fs *FileStore) Load(imsi string) (SubscriberState, bool, error) {
	if imsi == "" {
		return SubscriberState{}, false, fmt.Errorf("sqnstore: imsi is required")
	}
	data, err := fs.loadFile()
	if err != nil {
		return SubscriberState{}, false, err
	}
	rec, ok := data.Subscribers[imsi]
	if !ok {
		return SubscriberState{}, false, nil
	}
	state, err := rec.toState()
	if err != nil {
		return SubscriberState{}, false, err
	}
	return state, true, nil
}

func (fs *FileStore) Save(imsi string, state SubscriberState) error {
	if imsi == "" {
		return fmt.Errorf("sqnstore: imsi is required")
	}
	data, err := fs.loadFile()
	if err != nil {
		return err
	}
	now := time.Now
	if fs.Now != nil {
		now = fs.Now
	}
	state.UpdatedAt = now()
	rec, err := fromState(state)
	if err != nil {
		return err
	}
	data.Subscribers[imsi] = rec
	return fs.saveFile(data)
}

func (fs *FileStore) Reset(imsi string) error {
	if imsi == "" {
		return fmt.Errorf("sqnstore: imsi is required")
	}
	data, err := fs.loadFile()
	if err != nil {
		return err
	}
	delete(data.Subscribers, imsi)
	return fs.saveFile(data)
}

type fileData struct {
	Version     int                       `json:"version"`
	IndBits     int                       `json:"ind_bits"`
	ArraySize   int                       `json:"a"`
	Subscribers map[string]subscriberJSON `json:"subscribers"`
}

type subscriberJSON struct {
	SeqMS     []uint64 `json:"seqms"`
	SQNMSHex  string   `json:"sqnms_hex"`
	UpdatedAt string   `json:"updated_at"`
}

func newFileData() fileData {
	return fileData{
		Version:     storeVersion,
		IndBits:     IndBits,
		ArraySize:   ArraySize,
		Subscribers: map[string]subscriberJSON{},
	}
}

func (fs *FileStore) loadFile() (fileData, error) {
	data := newFileData()
	b, err := os.ReadFile(fs.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return data, nil
		}
		return data, err
	}
	if err := json.Unmarshal(b, &data); err != nil {
		return data, err
	}
	if data.Version != storeVersion {
		return data, fmt.Errorf("sqnstore: unsupported store version: %d", data.Version)
	}
	if data.IndBits != IndBits || data.ArraySize != ArraySize {
		return data, fmt.Errorf("sqnstore: store shape mismatch ind_bits=%d a=%d", data.IndBits, data.ArraySize)
	}
	if data.Subscribers == nil {
		data.Subscribers = map[string]subscriberJSON{}
	}
	return data, nil
}

func (fs *FileStore) saveFile(data fileData) error {
	if data.Subscribers == nil {
		data.Subscribers = map[string]subscriberJSON{}
	}
	payload, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(fs.Path)
	tmp, err := os.CreateTemp(dir, ".sqnstore-*")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.Remove(tmp.Name())
	}()
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), fs.Path)
}

func (s subscriberJSON) toState() (SubscriberState, error) {
	if len(s.SeqMS) != ArraySize {
		return SubscriberState{}, fmt.Errorf("sqnstore: seqms length must be %d", ArraySize)
	}
	var seqs [ArraySize]uint64
	copy(seqs[:], s.SeqMS)
	sqn, err := ParseSQNHex(s.SQNMSHex)
	if err != nil {
		return SubscriberState{}, err
	}
	var updatedAt time.Time
	if s.UpdatedAt != "" {
		updatedAt, err = time.Parse(time.RFC3339, s.UpdatedAt)
		if err != nil {
			return SubscriberState{}, fmt.Errorf("sqnstore: invalid updated_at: %w", err)
		}
	}
	return SubscriberState{
		SeqMS:     seqs,
		SQNMS:     sqn,
		UpdatedAt: updatedAt,
	}, nil
}

func fromState(state SubscriberState) (subscriberJSON, error) {
	sqnHex, err := FormatSQNHex(state.SQNMS)
	if err != nil {
		return subscriberJSON{}, err
	}
	updated := ""
	if !state.UpdatedAt.IsZero() {
		updated = state.UpdatedAt.UTC().Format(time.RFC3339)
	}
	seqms := make([]uint64, ArraySize)
	copy(seqms, state.SeqMS[:])
	return subscriberJSON{
		SeqMS:     seqms,
		SQNMSHex:  sqnHex,
		UpdatedAt: updated,
	}, nil
}
