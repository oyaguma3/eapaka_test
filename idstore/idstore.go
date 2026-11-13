// Package idstore は、実行をまたいで使う識別子と履歴を保存する（設計書 §4.1）。
//
// IMSI と EAP メソッドごとに、サーバから受け取った仮名と、サーバが送ってきた
// AT_IV のハッシュの履歴（規則 A-02 の判定に使う）を持つ。SQN ストアとは別のファイルで、
// パーミッションは 0600。保存は一時ファイルに書いてから rename する。
package idstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// Method は EAP メソッドの種別。仮名や再認証 ID はメソッドごとに別に持つ（RFC 9048 §7）。
type Method string

const (
	MethodAKA      Method = "aka"
	MethodAKAPrime Method = "aka_prime"
)

// MethodFor は EAP タイプ（23 / 50）を Method に変換する。
func MethodFor(eapType uint8) Method {
	if eapType == 50 {
		return MethodAKAPrime
	}
	return MethodAKA
}

// HistoryLimit は、履歴に残すハッシュの数（新しいものから）。
const HistoryLimit = 64

// Pseudonym はサーバから受け取った仮名（AT_NEXT_PSEUDONYM。レルムを含まないユーザー名部分）。
type Pseudonym struct {
	Username string    `json:"username"`
	IssuedAt time.Time `json:"issued_at"`
}

// Reauth は高速再認証のコンテキスト（RFC 4187 §5、RFC 9048 §3.3）。鍵を含むので、
// ファイルは 0600 で保存し、ログやトレースには出さない。
type Reauth struct {
	Identity     string    `json:"identity"`           // AT_NEXT_REAUTH_ID（完全な NAI）
	MK           HexBytes  `json:"mk,omitzero"`        // EAP-AKA の MK（20 バイト）
	KRe          HexBytes  `json:"k_re,omitzero"`      // EAP-AKA' の K_re（32 バイト）
	KEncr        HexBytes  `json:"k_encr"`             // フル認証の K_encr（再認証でもそのまま使う）
	KAut         HexBytes  `json:"k_aut"`              // フル認証の K_aut（再認証でもそのまま使う）
	CounterFloor uint16    `json:"counter_floor"`      // 受け入れる AT_COUNTER の下限
	NetName      string    `json:"net_name,omitempty"` // EAP-AKA' のネットワーク名（違えば再認証しない）
	IssuedAt     time.Time `json:"issued_at"`
}

// HexBytes は JSON で 16 進文字列として表すバイト列。
type HexBytes []byte

func (b HexBytes) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(b)), nil
}

func (b *HexBytes) UnmarshalText(text []byte) error {
	v, err := hex.DecodeString(string(text))
	if err != nil {
		return err
	}
	*b = v
	return nil
}

// History は、再利用してはならない値のハッシュ（SHA-256 の 16 進）の履歴。
type History struct {
	IVSHA256     []string `json:"iv_sha256,omitempty"`
	NonceSSHA256 []string `json:"nonce_s_sha256,omitempty"`
}

// Entry は IMSI とメソッドの組ごとの記録。
type Entry struct {
	Pseudonym *Pseudonym `json:"pseudonym,omitempty"`
	Reauth    *Reauth    `json:"reauth,omitempty"`
	// UsedReauth は直近に使った再認証コンテキスト。使うときに Reauth から移す
	// （交換が完了しなくても再利用しない、RFC 4187 §4.1.1.8）。再利用の異常系の注入に使う。
	UsedReauth *Reauth `json:"used_reauth,omitempty"`
	History    History `json:"history,omitzero"`
}

// AddNonceS は AT_NONCE_S のハッシュを履歴に足し、既に履歴にあったかを返す（規則 A-03）。
func (e *Entry) AddNonceS(nonce []byte) (reused bool) {
	return addHash(&e.History.NonceSSHA256, nonce)
}

// AddIV は AT_IV のハッシュを履歴に足し、既に履歴にあったかを返す。
func (e *Entry) AddIV(iv []byte) (reused bool) {
	return addHash(&e.History.IVSHA256, iv)
}

func addHash(list *[]string, v []byte) bool {
	sum := sha256.Sum256(v)
	h := hex.EncodeToString(sum[:])
	if slices.Contains(*list, h) {
		return true
	}
	*list = append(*list, h)
	if over := len(*list) - HistoryLimit; over > 0 {
		*list = slices.Delete(*list, 0, over)
	}
	return false
}

// Store は識別子ストア。
type Store interface {
	Get(imsi string, m Method) (Entry, error)
	Put(imsi string, m Method, e Entry) error
	Reset(imsi string) error
}

type data struct {
	Version     int                         `json:"version"`
	Subscribers map[string]map[Method]Entry `json:"subscribers"`
}

func newData() data {
	return data{Version: 1, Subscribers: map[string]map[Method]Entry{}}
}

func (d *data) get(imsi string, m Method) Entry {
	return d.Subscribers[imsi][m]
}

func (d *data) put(imsi string, m Method, e Entry) {
	if d.Subscribers[imsi] == nil {
		d.Subscribers[imsi] = map[Method]Entry{}
	}
	d.Subscribers[imsi][m] = e
}

// MemoryStore はプロセスの中だけで持つストア。
type MemoryStore struct {
	mu sync.Mutex
	d  data
}

// NewMemoryStore は空の MemoryStore を作る。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{d: newData()}
}

func (s *MemoryStore) Get(imsi string, m Method) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.get(imsi, m), nil
}

func (s *MemoryStore) Put(imsi string, m Method, e Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.put(imsi, m, e)
	return nil
}

func (s *MemoryStore) Reset(imsi string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.d.Subscribers, imsi)
	return nil
}

// FileStore は JSON ファイルに保存するストア。同じファイルを複数のプロセスで同時に使わないこと。
type FileStore struct {
	Path string
}

func (s *FileStore) Get(imsi string, m Method) (Entry, error) {
	d, err := s.load()
	if err != nil {
		return Entry{}, err
	}
	return d.get(imsi, m), nil
}

func (s *FileStore) Put(imsi string, m Method, e Entry) error {
	d, err := s.load()
	if err != nil {
		return err
	}
	d.put(imsi, m, e)
	return s.save(d)
}

func (s *FileStore) Reset(imsi string) error {
	d, err := s.load()
	if err != nil {
		return err
	}
	delete(d.Subscribers, imsi)
	return s.save(d)
}

func (s *FileStore) load() (data, error) {
	b, err := os.ReadFile(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return newData(), nil
	}
	if err != nil {
		return data{}, fmt.Errorf("idstore: read %s: %w", s.Path, err)
	}
	d := newData()
	if err := json.Unmarshal(b, &d); err != nil {
		return data{}, fmt.Errorf("idstore: parse %s: %w", s.Path, err)
	}
	if d.Version != 1 {
		return data{}, fmt.Errorf("idstore: %s has unsupported version %d", s.Path, d.Version)
	}
	if d.Subscribers == nil {
		d.Subscribers = map[string]map[Method]Entry{}
	}
	return d, nil
}

func (s *FileStore) save(d data) error {
	// 出力を安定させるため、空になった加入者は消す
	maps.DeleteFunc(d.Subscribers, func(_ string, v map[Method]Entry) bool { return len(v) == 0 })
	b, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("idstore: encode: %w", err)
	}
	dir := filepath.Dir(s.Path)
	tmp, err := os.CreateTemp(dir, ".idstore-*")
	if err != nil {
		return fmt.Errorf("idstore: create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.Path)
}
