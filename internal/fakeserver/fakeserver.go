// Package fakeserver は、テスト用の疑似 RADIUS＋EAP-AKA/AKA' サーバ（設計書 §9.2）。
//
// 同じプロセス内で UDP の RADIUS サーバを立て、go-eapaka を使ってサーバ側の
// EAP-AKA/AKA' を実装する。Faults で RFC 違反を注入でき、ツールの準拠性チェッカが
// 違反を検出できるかを確かめるのに使う。
package fakeserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/oyaguma3/eapaka_test/eap"
	"github.com/oyaguma3/eapaka_test/radiusc"

	eapaka "github.com/oyaguma3/go-eapaka"
	"github.com/wmnsk/milenage"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

// Config は疑似サーバの設定。
type Config struct {
	Secret string
	KI     []byte // 16 バイト
	OPC    []byte // 16 バイト

	// Method は提示する EAP メソッド（eapaka.TypeAKA か eapaka.TypeAKAPrime）。0 なら EAP-AKA。
	Method uint8
	// NetName は EAP-AKA' の AT_KDF_INPUT に入れるネットワーク名。
	NetName string
	// KDFOffer は EAP-AKA' の AT_KDF の offer。空なら [1]。
	KDFOffer []uint16
	// AMF は AUTN に入れる AMF。0 なら 0x8000（分離ビットが 1）。
	AMF uint16
	// SQN は最初の Challenge の SQN。0 なら 32（SEQ=1、IND=0）。Challenge ごとに 32 ずつ増やす。
	SQN uint64
	// IdentityRequest が空でなければ、Challenge の前に AKA-Identity を要求する。
	// "permanent"、"fullauth"、"any" のいずれか。
	IdentityRequest string
	// Bidding は EAP-AKA の Challenge に入れる AT_BIDDING。""（入れない）、"d0"、"d1"（D ビットを立てる）。
	Bidding string
	// NakMethods は、ピアの Nak を受けたときに切り替えてよいメソッド。空なら Nak を受けたら失敗にする。
	NakMethods []uint8

	Faults Faults
}

// Faults は疑似サーバに注入する RFC 違反。
type Faults struct {
	// RADIUS 層（R-01〜R-07）
	CorruptMessageAuthenticator bool // R-01: 応答の Message-Authenticator を壊す
	OmitMessageAuthenticator    bool // R-02: 応答に Message-Authenticator を付けない
	AcceptWithoutEAP            bool // R-03a: Access-Accept に EAP-Message を入れない
	AcceptWithEAPFailure        bool // R-03a: Access-Accept に EAP-Failure を入れる
	RejectWithEAPSuccess        bool // R-03a: Access-Reject に EAP-Success を入れる
	ChallengeWithoutEAP         bool // R-03b: 最初の Access-Challenge に EAP-Message を入れない
	WrongSuccessIdentifier      bool // R-04: EAP-Success/Failure の Identifier を 1 ずらす
	EarlyAccept                 bool // R-05: EAP-Response/Identity を受けたらすぐ Access-Accept を返す
	SwitchMethod                bool // R-06: Challenge の応答を受けたら、別のメソッドの Challenge を送る
	MPPESaltMSBClear            bool // R-07: MS-MPPE-Recv-Key の Salt の最上位ビットを 0 にする
	MPPEDuplicateSalt           bool // R-07: MS-MPPE-Send-Key の Salt を Recv-Key と同じにする
	MPPEWrongKey                bool // X2: MS-MPPE-Recv-Key に MSK と違う値を入れる
	MPPESwapped                 bool // X2: Send-Key と Recv-Key に入れる MSK の半分を入れ替える

	// EAP-AKA/AKA' 層
	WrongAUTN            bool // AUTN の MAC-A を壊す（ピアは Authentication-Reject を返すべき）
	ClearSeparationBit   bool // A-12: AMF の分離ビットを 0 にする
	EmptyKdfInput        bool // A-13: AT_KDF_INPUT のネットワーク名を空にする
	CorruptRequestMAC    bool // A-18: Challenge の AT_MAC を壊す
	BadKdfReoffer        bool // A-17: KDF の再提示で元の offer を落とす
	UnknownNonSkippable  bool // A-16: 未知のスキップ不可属性（タイプ 100）を Challenge に入れる
	NonZeroReserved      bool // AT_RAND の Reserved を 0 以外にして、受信したバイト列のまま MAC を付ける
	BiddingInAKAPrime    bool // A-09: EAP-AKA' の Challenge に AT_BIDDING（D=1）を入れる
	IgnoreResponseResult bool // ピアの応答の RES と MAC を確かめずに成功させる
}

// Event は疑似サーバが受け取った EAP-Response の記録。
type Event struct {
	Type    uint8
	Subtype uint8 // EAP-AKA/AKA' のときだけ
}

// Server は疑似 RADIUS サーバ。
type Server struct {
	cfg  Config
	conn net.PacketConn
	srv  *radius.PacketServer

	mu       sync.Mutex
	sessions map[string]*session
	sqn      uint64
	events   []Event
}

type session struct {
	identity string // 鍵導出に使う ID
	method   uint8
	lastID   uint8 // 直前に受けた EAP-Response の Identifier

	kAut     []byte
	msk      []byte
	xres     []byte
	kdfOffer []uint16
	switched bool
}

// Start は疑似サーバを 127.0.0.1 の空いているポートで起動する。
func Start(cfg Config) (*Server, error) {
	if len(cfg.KI) != 16 || len(cfg.OPC) != 16 {
		return nil, errors.New("fakeserver: KI and OPC must be 16 bytes")
	}
	if cfg.Secret == "" {
		return nil, errors.New("fakeserver: secret is required")
	}
	if cfg.Method == 0 {
		cfg.Method = eapaka.TypeAKA
	}
	if len(cfg.KDFOffer) == 0 {
		cfg.KDFOffer = []uint16{eapaka.KDFAKAPrimeWithCKIK}
	}
	if cfg.AMF == 0 {
		cfg.AMF = 0x8000
	}
	if cfg.SQN == 0 {
		cfg.SQN = 32
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, conn: conn, sessions: map[string]*session{}, sqn: cfg.SQN}
	s.srv = &radius.PacketServer{
		Handler:      radius.HandlerFunc(s.serve),
		SecretSource: radius.StaticSecretSource([]byte(cfg.Secret)),
	}
	go s.srv.Serve(conn)
	return s, nil
}

// StartT は Start を呼び、テストの終了時に停止する。
func StartT(t testing.TB, cfg Config) *Server {
	t.Helper()
	s, err := Start(cfg)
	if err != nil {
		t.Fatalf("fakeserver: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// Addr は待ち受けているアドレスを返す。
func (s *Server) Addr() string { return s.conn.LocalAddr().String() }

// Close はサーバを止める。
func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

// Events は受け取った EAP-Response の一覧を返す。
func (s *Server) Events() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.events...)
}

// reply は RADIUS 応答の中身。
type reply struct {
	code  radius.Code
	eap   []byte // nil なら EAP-Message を付けない
	state []byte
	msk   []byte // nil でなければ MS-MPPE 鍵を付ける
}

func (s *Server) serve(w radius.ResponseWriter, r *radius.Request) {
	s.mu.Lock()
	rep := s.handle(r.Packet)
	s.mu.Unlock()
	if err := s.write(w, r.Packet, rep); err != nil {
		panic(fmt.Sprintf("fakeserver: write response: %v", err))
	}
}

func (s *Server) handle(req *radius.Packet) reply {
	raw, ok, err := radiusc.LookupEAPMessage(req)
	if err != nil || !ok {
		return reply{code: radius.CodeAccessReject}
	}
	pkt, err := eap.Parse(raw)
	if err != nil || pkt.Code != eap.CodeResponse {
		return reply{code: radius.CodeAccessReject}
	}
	s.events = append(s.events, eventOf(pkt, raw))

	state := rfc2865.State_Get(req)
	if len(state) == 0 {
		if pkt.Type != eap.TypeIdentity {
			return s.failure(nil, pkt.Identifier, nil)
		}
		return s.startSession(pkt)
	}
	sess := s.sessions[string(state)]
	if sess == nil {
		return s.failure(nil, pkt.Identifier, nil)
	}
	sess.lastID = pkt.Identifier
	if pkt.Type == eap.TypeNak {
		// 希望されたメソッドのうち、切り替えてよい最初のものに切り替える（RFC 3748 §5.3.1）
		for _, m := range pkt.TypeData {
			if slices.Contains(s.cfg.NakMethods, m) {
				sess.method = m
				return s.challenge(sess, state, nil)
			}
		}
		return s.failure(sess, pkt.Identifier, state)
	}
	if pkt.Type != eapaka.TypeAKA && pkt.Type != eapaka.TypeAKAPrime {
		return s.failure(sess, pkt.Identifier, state)
	}
	akaPkt, err := eapaka.ParseWithOptions(raw, eapaka.ParseOptions{AllowBiddingInAKAPrime: true})
	if err != nil {
		return s.failure(sess, pkt.Identifier, state)
	}
	switch akaPkt.Subtype {
	case eapaka.SubtypeIdentity:
		for _, a := range akaPkt.Attributes {
			if id, ok := a.(*eapaka.AtIdentity); ok {
				sess.identity = id.Identity
			}
		}
		return s.challenge(sess, state, nil)
	case eapaka.SubtypeChallenge:
		return s.challengeResponse(sess, state, raw, akaPkt)
	default:
		// Authentication-Reject、Client-Error、Synchronization-Failure など
		return s.failure(sess, pkt.Identifier, state)
	}
}

func eventOf(pkt eap.Packet, raw []byte) Event {
	ev := Event{Type: pkt.Type}
	if (pkt.Type == eap.TypeAKA || pkt.Type == eap.TypeAKAPrime) && len(raw) > 5 {
		ev.Subtype = raw[5]
	}
	return ev
}

func (s *Server) startSession(pkt eap.Packet) reply {
	state := make([]byte, 8)
	_, _ = rand.Read(state)
	sess := &session{identity: string(pkt.TypeData), method: s.cfg.Method, lastID: pkt.Identifier}
	s.sessions[string(state)] = sess

	if s.cfg.Faults.EarlyAccept {
		return reply{code: radius.CodeAccessAccept, eap: s.result(eap.CodeSuccess, sess.lastID)}
	}
	if s.cfg.IdentityRequest != "" {
		var attr eapaka.Attribute
		switch s.cfg.IdentityRequest {
		case "permanent":
			attr = &eapaka.AtPermanentIdReq{}
		case "fullauth":
			attr = &eapaka.AtFullauthIdReq{}
		default:
			attr = &eapaka.AtAnyIdReq{}
		}
		req := &eapaka.Packet{
			Code: eapaka.CodeRequest, Identifier: sess.lastID + 1, Type: sess.method,
			Subtype: eapaka.SubtypeIdentity, Attributes: []eapaka.Attribute{attr},
		}
		b, err := req.Marshal()
		if err != nil {
			panic(err)
		}
		return reply{code: radius.CodeAccessChallenge, eap: b, state: state}
	}
	rep := s.challenge(sess, state, nil)
	if s.cfg.Faults.ChallengeWithoutEAP {
		rep.eap = nil
	}
	return rep
}

func (s *Server) challengeResponse(sess *session, state, raw []byte, resp *eapaka.Packet) reply {
	if sess.switched {
		return s.failure(sess, sess.lastID, state)
	}
	// AT_KDF だけの応答は KDF 交渉（RFC 9048 §3.2）
	if values := eapaka.KdfValuesFromAttributes(resp.Attributes); len(values) > 0 && len(values) == len(resp.Attributes) {
		selected, err := eapaka.ValidateKdfResponse(sess.kdfOffer, values)
		if err != nil {
			return s.failure(sess, sess.lastID, state)
		}
		reoffer, err := eapaka.BuildKdfReofferAttributes(sess.kdfOffer, selected)
		if err != nil {
			return s.failure(sess, sess.lastID, state)
		}
		if s.cfg.Faults.BadKdfReoffer {
			reoffer = []eapaka.Attribute{&eapaka.AtKdf{KDF: selected}}
		}
		return s.challenge(sess, state, reoffer)
	}

	ok := s.cfg.Faults.IgnoreResponseResult
	if !ok {
		macOK, err := eapaka.VerifyMacRaw(raw, sess.kAut, nil)
		ok = err == nil && macOK && bytes.Equal(findRes(resp), sess.xres)
	}
	if !ok {
		return s.failure(sess, sess.lastID, state)
	}
	if s.cfg.Faults.SwitchMethod {
		sess.switched = true
		if sess.method == eapaka.TypeAKA {
			sess.method = eapaka.TypeAKAPrime
		} else {
			sess.method = eapaka.TypeAKA
		}
		return s.challenge(sess, state, nil)
	}
	return s.success(sess, state)
}

func findRes(p *eapaka.Packet) []byte {
	for _, a := range p.Attributes {
		if res, ok := a.(*eapaka.AtRes); ok {
			return res.Res
		}
	}
	return nil
}

// challenge は新しい認証ベクタで AKA-Challenge を組み立てる。kdfAttrs が nil なら設定の offer を使う。
func (s *Server) challenge(sess *session, state []byte, kdfAttrs []eapaka.Attribute) reply {
	f := s.cfg.Faults
	rnd := make([]byte, 16)
	_, _ = rand.Read(rnd)
	amf := s.cfg.AMF
	if f.ClearSeparationBit {
		amf &^= 0x8000
	}
	sqn := s.sqn
	s.sqn += 32

	mil := milenage.NewWithOPc(s.cfg.KI, s.cfg.OPC, rnd, sqn, amf)
	macA, err := mil.F1()
	if err != nil {
		panic(err)
	}
	res, ck, ik, ak, err := mil.F2345()
	if err != nil {
		panic(err)
	}
	var sqnBytes [8]byte
	binary.BigEndian.PutUint64(sqnBytes[:], sqn)
	autn := make([]byte, 16)
	for i := range 6 {
		autn[i] = sqnBytes[2+i] ^ ak[i]
	}
	binary.BigEndian.PutUint16(autn[6:8], amf)
	copy(autn[8:], macA)
	if f.WrongAUTN {
		autn[15] ^= 0x01
	}

	attrs := []eapaka.Attribute{&eapaka.AtRand{Rand: rnd}, &eapaka.AtAutn{Autn: autn}}
	if sess.method == eapaka.TypeAKAPrime {
		ckp, ikp, err := eapaka.DeriveCKPrimeIKPrime(ck, ik, s.cfg.NetName, autn)
		if err != nil {
			panic(err)
		}
		keys := eapaka.DeriveKeysAKAPrime(sess.identity, ckp, ikp)
		sess.kAut, sess.msk = keys.K_aut, keys.MSK
		if f.EmptyKdfInput {
			// go-eapaka は空のネットワーク名を組み立てないので、値（長さ 0）を直接入れる
			attrs = append(attrs, &eapaka.GenericAttribute{AttrType: eapaka.AT_KDF_INPUT, Data: []byte{0, 0}})
		} else {
			attrs = append(attrs, &eapaka.AtKdfInput{NetworkName: s.cfg.NetName})
		}
		if kdfAttrs == nil {
			sess.kdfOffer = s.cfg.KDFOffer
			kdfAttrs, err = eapaka.BuildKdfOfferAttributes(sess.kdfOffer)
			if err != nil {
				panic(err)
			}
		}
		attrs = append(attrs, kdfAttrs...)
	} else {
		keys := eapaka.DeriveKeysAKA(sess.identity, ck, ik)
		sess.kAut, sess.msk = keys.K_aut, keys.MSK
	}
	if sess.method == eapaka.TypeAKA && s.cfg.Bidding != "" {
		b := &eapaka.AtBidding{}
		b.SetAKAPrime(s.cfg.Bidding == "d1")
		attrs = append(attrs, b)
	}
	if sess.method == eapaka.TypeAKAPrime && f.BiddingInAKAPrime {
		// go-eapaka は EAP-AKA' の AT_BIDDING を組み立てないので、仮の型で組み立ててから書き換える
		attrs = append(attrs, &eapaka.GenericAttribute{AttrType: placeholderType, Data: []byte{0x80, 0}})
	}
	if f.UnknownNonSkippable {
		attrs = append(attrs, &eapaka.GenericAttribute{AttrType: 100, Data: []byte{0, 0}})
	}
	attrs = append(attrs, &eapaka.AtMac{MAC: make([]byte, 16)})
	sess.xres = res

	req := &eapaka.Packet{
		Code: eapaka.CodeRequest, Identifier: sess.lastID + 1, Type: sess.method,
		Subtype: eapaka.SubtypeChallenge, Attributes: attrs,
	}
	if err := req.CalculateAndSetMac(sess.kAut); err != nil {
		panic(err)
	}
	b, err := req.Marshal()
	if err != nil {
		panic(err)
	}
	if sess.method == eapaka.TypeAKAPrime && f.BiddingInAKAPrime {
		retype(b, placeholderType, eapaka.AT_BIDDING)
		if err := eapaka.CalculateAndSetMacRaw(b, sess.kAut, nil); err != nil {
			panic(err)
		}
	}
	if f.NonZeroReserved {
		// 先頭の属性は AT_RAND。値フィールドの先頭 2 バイトが Reserved
		b[8+2], b[8+3] = 0x5a, 0xa5
		if err := eapaka.CalculateAndSetMacRaw(b, sess.kAut, nil); err != nil {
			panic(err)
		}
	}
	if f.CorruptRequestMAC {
		b[len(b)-1] ^= 0xff // AT_MAC は最後の属性
	}
	return reply{code: radius.CodeAccessChallenge, eap: b, state: state}
}

func (s *Server) success(sess *session, state []byte) reply {
	f := s.cfg.Faults
	rep := reply{code: radius.CodeAccessAccept, eap: s.result(eap.CodeSuccess, sess.lastID), msk: sess.msk}
	switch {
	case f.AcceptWithoutEAP:
		rep.eap = nil
	case f.AcceptWithEAPFailure:
		rep.eap = s.result(eap.CodeFailure, sess.lastID)
	}
	delete(s.sessions, string(state))
	return rep
}

func (s *Server) failure(sess *session, id uint8, state []byte) reply {
	rep := reply{code: radius.CodeAccessReject, eap: s.result(eap.CodeFailure, id)}
	if s.cfg.Faults.RejectWithEAPSuccess {
		rep.eap = s.result(eap.CodeSuccess, id)
	}
	if sess != nil {
		delete(s.sessions, string(state))
	}
	return rep
}

func (s *Server) result(code, id uint8) []byte {
	if s.cfg.Faults.WrongSuccessIdentifier {
		id++
	}
	b, _ := eap.Packet{Code: code, Identifier: id}.Encode()
	return b
}

func (s *Server) write(w radius.ResponseWriter, req *radius.Packet, rep reply) error {
	f := s.cfg.Faults
	resp := req.Response(rep.code)
	if rep.eap != nil {
		if err := radiusc.AddEAPMessage(resp, rep.eap); err != nil {
			return err
		}
	}
	if rep.state != nil {
		if err := rfc2865.State_Set(resp, rep.state); err != nil {
			return err
		}
	}
	if rep.msk != nil {
		if err := addMPPEKeys(resp, rep.msk, []byte(s.cfg.Secret), req.Authenticator[:], f); err != nil {
			return err
		}
	}
	if !f.OmitMessageAuthenticator {
		// 応答の Message-Authenticator は、Authenticator 欄を Request Authenticator にして計算する（RFC 3579 §3.2）
		if err := rfc2869.MessageAuthenticator_Set(resp, make([]byte, 16)); err != nil {
			return err
		}
		b, err := resp.MarshalBinary()
		if err != nil {
			return err
		}
		mac := hmac.New(md5.New, []byte(s.cfg.Secret))
		mac.Write(b)
		sum := mac.Sum(nil)
		if f.CorruptMessageAuthenticator {
			sum[0] ^= 0xff
		}
		if err := rfc2869.MessageAuthenticator_Set(resp, sum); err != nil {
			return err
		}
	}
	return w.Write(resp)
}

const (
	vendorMicrosoft = 311
	msMPPESendKey   = 16
	msMPPERecvKey   = 17
)

// addMPPEKeys は RFC 5216 §2.3 の慣行どおり、Recv-Key に MSK[0:32]、Send-Key に MSK[32:64] を入れる。
func addMPPEKeys(p *radius.Packet, msk, secret, reqAuth []byte, f Faults) error {
	recvKey, sendKey := bytes.Clone(msk[:32]), msk[32:64]
	if f.MPPESwapped {
		recvKey, sendKey = bytes.Clone(sendKey), recvKey
	}
	if f.MPPEWrongKey {
		recvKey[0] ^= 0xff
	}
	recv, err := eapaka.EncryptMPPEKey(recvKey, secret, reqAuth)
	if err != nil {
		return err
	}
	send, err := eapaka.EncryptMPPEKey(sendKey, secret, reqAuth)
	if err != nil {
		return err
	}
	if f.MPPESaltMSBClear {
		recv[0] &^= 0x80
	}
	if f.MPPEDuplicateSalt {
		copy(send[:2], recv[:2])
	}
	for _, kv := range []struct {
		typ byte
		val []byte
	}{{msMPPESendKey, send}, {msMPPERecvKey, recv}} {
		tlv := append([]byte{kv.typ, byte(2 + len(kv.val))}, kv.val...)
		vsa, err := radius.NewVendorSpecific(vendorMicrosoft, tlv)
		if err != nil {
			return err
		}
		p.Add(rfc2865.VendorSpecific_Type, vsa)
	}
	return nil
}

// placeholderType は、go-eapaka が組み立てない属性を入れるときの仮の型（未割り当てのスキップ可能な型）。
const placeholderType eapaka.AttributeType = 255

// retype は、パケット b の中の型 from の属性を型 to に書き換える。
func retype(b []byte, from, to eapaka.AttributeType) {
	for off := 8; off+2 <= len(b) && b[off+1] != 0; off += int(b[off+1]) * 4 {
		if eapaka.AttributeType(b[off]) == from {
			b[off] = byte(to)
		}
	}
}
