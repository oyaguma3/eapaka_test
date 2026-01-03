package sqnstore

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFileStoreSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sqn.json")
	fixed := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	store := &FileStore{
		Path: path,
		Now: func() time.Time {
			return fixed
		},
	}

	var state SubscriberState
	state.SeqMS[3] = 7
	state.SQNMS = 0x1234

	if err := store.Save("440100123456789", state); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	loaded, ok, err := store.Load("440100123456789")
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if !ok {
		t.Fatalf("expected record to exist")
	}
	if loaded.SeqMS[3] != 7 {
		t.Fatalf("expected seqms[3]=7, got %d", loaded.SeqMS[3])
	}
	if loaded.SQNMS != 0x1234 {
		t.Fatalf("expected sqnms=0x1234, got 0x%x", loaded.SQNMS)
	}
	if !loaded.UpdatedAt.Equal(fixed) {
		t.Fatalf("expected updated_at %v, got %v", fixed, loaded.UpdatedAt)
	}
}

func TestFileStoreReset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sqn.json")
	store := &FileStore{Path: path}

	if err := store.Save("440100123456789", SubscriberState{}); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	if err := store.Reset("440100123456789"); err != nil {
		t.Fatalf("reset failed: %v", err)
	}
	_, ok, err := store.Load("440100123456789")
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if ok {
		t.Fatalf("expected record to be removed")
	}
}

func TestFileStoreLoadMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.json")
	store := &FileStore{Path: path}

	_, ok, err := store.Load("440100123456789")
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if ok {
		t.Fatalf("expected missing record")
	}
}
