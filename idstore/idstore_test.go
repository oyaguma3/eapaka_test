package idstore

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStores(t *testing.T) {
	stores := map[string]Store{
		"memory": NewMemoryStore(),
		"file":   &FileStore{Path: filepath.Join(t.TempDir(), "ids.json")},
	}
	for name, s := range stores {
		t.Run(name, func(t *testing.T) {
			e, err := s.Get("440100123456789", MethodAKA)
			if err != nil || e.Pseudonym != nil {
				t.Fatalf("Get on an empty store = %+v, %v", e, err)
			}
			e.Pseudonym = &Pseudonym{Username: "2abc", IssuedAt: time.Unix(1700000000, 0).UTC()}
			if reused := e.AddIV([]byte("iv-1")); reused {
				t.Fatal("first IV reported as reused")
			}
			if err := s.Put("440100123456789", MethodAKA, e); err != nil {
				t.Fatal(err)
			}
			got, err := s.Get("440100123456789", MethodAKA)
			if err != nil || got.Pseudonym == nil || got.Pseudonym.Username != "2abc" {
				t.Fatalf("Get = %+v, %v", got, err)
			}
			if !got.AddIV([]byte("iv-1")) {
				t.Error("stored IV not reported as reused")
			}
			// メソッドごとに別の記録
			if other, _ := s.Get("440100123456789", MethodAKAPrime); other.Pseudonym != nil {
				t.Error("AKA' entry shares the AKA pseudonym")
			}
			if err := s.Reset("440100123456789"); err != nil {
				t.Fatal(err)
			}
			if got, _ := s.Get("440100123456789", MethodAKA); got.Pseudonym != nil {
				t.Error("Reset did not clear the entry")
			}
		})
	}
}

func TestFileStorePermissionAndVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ids.json")
	s := &FileStore{Path: path}
	if err := s.Put("1", MethodAKA, Entry{Pseudonym: &Pseudonym{Username: "2x"}}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("permission = %o, want 600", perm)
	}
	if err := os.WriteFile(path, []byte(`{"version":2,"subscribers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("1", MethodAKA); err == nil {
		t.Error("unsupported version accepted")
	}
}

func TestHistoryLimit(t *testing.T) {
	var e Entry
	for i := range HistoryLimit + 5 {
		e.AddIV([]byte{byte(i)})
	}
	if len(e.History.IVSHA256) != HistoryLimit {
		t.Errorf("history length = %d, want %d", len(e.History.IVSHA256), HistoryLimit)
	}
	if e.AddIV([]byte{0}) {
		t.Error("the oldest IV should have been dropped from the history")
	}
}
