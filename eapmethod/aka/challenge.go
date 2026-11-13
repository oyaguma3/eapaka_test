package aka

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/oyaguma3/eapaka_test/conformance"
	"github.com/oyaguma3/eapaka_test/eap"
	"github.com/oyaguma3/eapaka_test/idstore"
	"github.com/oyaguma3/eapaka_test/sqnstore"

	eapaka "github.com/oyaguma3/go-eapaka"
	"github.com/wmnsk/milenage"
)

// handleChallenge は EAP-Request/AKA-Challenge（AKA'-Challenge）を処理する。
//
// 処理の順番は RFC 4187 §9.3・§10.15 と RFC 9048 §3 に合わせる。
//  1. EAP-AKA' では AT_KDF の交渉と AT_KDF_INPUT の確認
//  2. AUTN の検証（誤りなら Authentication-Reject）、EAP-AKA' の AMF 分離ビット
//  3. SQN の範囲（範囲外なら Synchronization-Failure）。保存はまだしない
//  4. AT_MAC の検証（誤りなら Client-Error）。受信したバイト列のまま検証する
//  5. EAP-AKA の AT_BIDDING（D=1 なら Authentication-Reject、RFC 9048 §4）
//  6. SQN の保存
func (m *Method) handleChallenge(req *eapaka.Packet, raw []byte, sess *eap.Session) (*eap.Packet, error) {
	rec := sess.Conformance
	rand, autn, ok := challengeVectors(req)
	if !ok {
		rec.Report("A-16", "AKA-Challenge lacks a valid AT_RAND or AT_AUTN")
		return m.clientError(req)
	}

	var netName string
	if req.Type == eapaka.TypeAKAPrime {
		if resp, done, err := m.negotiateKdf(req, rec); done || err != nil {
			return resp, err
		}
		var resp *eap.Packet
		netName, resp = m.kdfInputNetName(req, sess)
		if resp != nil {
			return resp, nil
		}
	}

	res, ck, ik, ak, err := m.computeVectors(rand)
	if err != nil {
		return nil, err
	}
	sqnBytes, amf, err := m.decodeAutn(autn, ak)
	if err != nil {
		return nil, err
	}
	if ok, err := m.verifyMacA(rand, sqnBytes, amf, autn); err != nil {
		return nil, err
	} else if !ok {
		return m.authenticationReject(req), nil
	}
	if !bytes.Equal(amf, m.amfBytes()) {
		sess.Warnf("AUTN AMF %x differs from sim.amf %x", amf, m.amfBytes())
	}
	if req.Type == eapaka.TypeAKAPrime && amf[0]&0x80 == 0 {
		// RFC 9048 §3.3: 分離ビットが 0 なら AUTN が誤っているのと同じに扱う
		rec.Report("A-12", "AMF %x in EAP-AKA' AUTN does not have the separation bit set", amf)
		return m.authenticationReject(req), nil
	}

	var sqnState *sqnstore.SubscriberState
	if m.store != nil {
		state, accepted, err := m.checkSQN(sqnBytes)
		if err != nil {
			return nil, err
		}
		sqnState = &state
		if !accepted {
			auts, err := m.generateAUTS(rand)
			if err != nil {
				return nil, err
			}
			return m.synchronizationFailure(req, auts)
		}
	}

	identity := sess.InnerIdentity
	if identity == "" {
		identity = sess.OuterIdentity
	}
	if identity == "" {
		return nil, fmt.Errorf("aka: inner identity is required")
	}
	keys, err := m.deriveKeys(identity, ck, ik, netName, autn)
	if err != nil {
		return nil, err
	}
	kAut := keys.kAut
	macOK, err := eapaka.VerifyMacRaw(raw, kAut, nil)
	switch {
	case errors.Is(err, eapaka.ErrMacNotFound):
		rec.Report("A-18", "AKA-Challenge lacks AT_MAC")
		return m.clientError(req)
	case err != nil:
		rec.Report("A-16", "AKA-Challenge AT_MAC cannot be verified: %v", err)
		return m.clientError(req)
	case !macOK:
		rec.Report("A-18", "AKA-Challenge AT_MAC is invalid")
		return m.clientError(req)
	}

	if req.Type == eapaka.TypeAKA {
		if b := findBidding(req); b != nil {
			obs := &eap.BiddingObs{Method: req.Type, DBit: b.SupportsAKAPrime(), Action: "ignore"}
			sess.Obs.Bidding = obs
			if obs.DBit && m.biddingPolicy == "reject" {
				// サーバは AKA' に対応しているのに AKA が使われた（bidding down）。
				// AUTN が不正だったのと同じに扱い、SQN は保存しない
				obs.Action = "reject"
				sess.Warnf("AT_BIDDING has the D bit set; rejecting EAP-AKA (bidding_policy=reject)")
				return m.authenticationReject(req), nil
			}
		}
	}
	if sqnState != nil {
		if err := m.saveSQN(*sqnState); err != nil {
			return nil, err
		}
	}

	ccValue, ccInclude, ccResp, err := m.checkcode(req, sess)
	if ccResp != nil || err != nil {
		return ccResp, err
	}
	if resp, done, err := m.processEncrData(req, keys.kEncr, sess); done || err != nil {
		return resp, err
	}

	action := m.faultAt(FaultAtChallengeResponse, sess)
	if resp, ok, err := m.replaceByFault(action, req); ok {
		return resp, err
	}
	if action == FaultWrongRES {
		res = bytes.Clone(res)
		res[0] ^= 0xff
	}
	mac := &eapaka.AtMac{MAC: make([]byte, 16)}
	attrs := []eapaka.Attribute{&eapaka.AtRes{Res: res}}
	// RFC 4187 §6.2: サーバが AT_RESULT_IND を送ってきたときだけ、応答にも入れられる
	useResultInd := m.resultInd && hasAttr[*eapaka.AtResultInd](req)
	if useResultInd {
		attrs = append(attrs, &eapaka.AtResultInd{})
	}
	if ccInclude {
		attrs = append(attrs, &eapaka.AtCheckcode{Checkcode: ccValue})
	}
	attrs = append(attrs, mac)
	resp := &eapaka.Packet{
		Code:       eapaka.CodeResponse,
		Identifier: req.Identifier,
		Type:       req.Type,
		Subtype:    eapaka.SubtypeChallenge,
		Attributes: attrs,
	}
	if err := resp.CalculateAndSetMac(kAut); err != nil {
		return nil, err
	}
	m.s.phase = phaseChallenged
	if useResultInd {
		// 双方が AT_RESULT_IND を使ったので、成功通知を受けるまで成功を受け入れない（§6.3.4）
		m.s.resultInd = true
		m.s.phase = phaseAwaitingResult
	}
	m.s.keys = keys
	sess.MSK = keys.msk
	sess.Obs.AuthType = "full"
	// Session-Id は「タイプ || RAND || AUTN」、Peer-Id は鍵の導出に使った ID（RFC 5247 付録 A、RFC 9048 §6）
	sess.Obs.PeerID = identity
	if req.Type == eapaka.TypeAKA {
		sess.Obs.SessionID, _ = eapaka.SessionIDAKA(rand, autn)
	} else {
		sess.Obs.SessionID, _ = eapaka.SessionIDAKAPrime(rand, autn)
	}
	// 認証が成功したら、受け取った再認証 ID で再認証の状態を置き換える（なければ破棄する）
	sess.Pending.Method, sess.Pending.AuthDone, sess.Pending.Reauth = req.Type, true, nil
	if m.s.nextReauthID != "" {
		sess.Pending.Reauth = &idstore.Reauth{
			Identity: m.s.nextReauthID, MK: keys.mk, KRe: keys.kRe, KEncr: keys.kEncr, KAut: keys.kAut,
			CounterFloor: 1, NetName: netName, IssuedAt: time.Now().UTC(),
		}
	}
	switch action {
	case FaultCorruptMAC:
		mac.MAC[len(mac.MAC)-1] ^= 0xff
		fallthrough
	case FaultWrongRES:
		// 応答が無効なので、サーバは成功を返してはならない（返せば R-05 で検出する）
		m.s.phase = phaseFailed
	}
	return toEAPPacket(resp)
}

// challengeVectors は AT_RAND と AT_AUTN の値を取り出す。どちらかがなければ ok は false。
func challengeVectors(req *eapaka.Packet) (rand, autn []byte, ok bool) {
	for _, attr := range req.Attributes {
		switch a := attr.(type) {
		case *eapaka.AtRand:
			rand = bytes.Clone(a.Rand)
		case *eapaka.AtAutn:
			autn = bytes.Clone(a.Autn)
		}
	}
	return rand, autn, len(rand) == 16 && len(autn) == 16
}

// negotiateKdf は EAP-AKA' の AT_KDF を処理する（RFC 9048 §3.2）。
// done が true なら resp をそのまま返す（AT_KDF だけの応答、Client-Error、Authentication-Reject）。
func (m *Method) negotiateKdf(req *eapaka.Packet, rec *conformance.Recorder) (resp *eap.Packet, done bool, err error) {
	offer := eapaka.KdfValuesFromAttributes(req.Attributes)
	if len(offer) == 0 {
		rec.Report("A-16", "AKA'-Challenge lacks AT_KDF")
		resp, err = m.clientError(req)
		return resp, true, err
	}
	supported := eapaka.KDFAKAPrimeWithCKIK

	if m.s.kdfOffer != nil {
		// AT_KDF だけの応答に対する再提示。選んだ値を元の offer の先頭に足しただけかを確かめる
		original := m.s.kdfOffer
		m.s.kdfOffer = nil
		if err := eapaka.ValidateKdfReoffer(original, offer, m.s.kdfSelected); err != nil {
			// RFC 9048 §3.2: AT_MAC が不正なときと同じに扱う
			rec.Report("A-17", "AT_KDF re-offer %v does not match the original offer %v: %v", offer, original, err)
			resp, err = m.clientError(req)
			return resp, true, err
		}
		return nil, false, nil
	}

	if err := eapaka.ValidateKdfOffer(offer); err != nil {
		rec.Report("A-16", "invalid AT_KDF offer %v: %v", offer, err)
		resp, err = m.clientError(req)
		return resp, true, err
	}
	if offer[0] == supported {
		return nil, false, nil
	}
	if !slices.Contains(offer, supported) {
		// 対応できる KDF がない
		return m.authenticationReject(req), true, nil
	}
	// 対応できる KDF を AT_KDF だけで返し、サーバの再提示を待つ
	m.s.kdfOffer = slices.Clone(offer)
	m.s.kdfSelected = supported
	m.s.phase = phaseKdfNegotiation
	resp, err = toEAPPacket(&eapaka.Packet{
		Code:       eapaka.CodeResponse,
		Identifier: req.Identifier,
		Type:       req.Type,
		Subtype:    eapaka.SubtypeChallenge,
		Attributes: []eapaka.Attribute{&eapaka.AtKdf{KDF: supported}},
	})
	return resp, true, err
}

// kdfInputNetName は AT_KDF_INPUT のネットワーク名を返す（RFC 9048 §3.1）。
// 認証を続けられないときは、返すべき応答を resp に入れる。
func (m *Method) kdfInputNetName(req *eapaka.Packet, sess *eap.Session) (netName string, resp *eap.Packet) {
	for _, attr := range req.Attributes {
		if a, ok := attr.(*eapaka.AtKdfInput); ok {
			netName = a.NetworkName
		}
	}
	if netName == "" {
		if !m.s.emptyKdfInputReported {
			sess.Conformance.Report("A-13", "AKA'-Challenge lacks AT_KDF_INPUT")
		}
		if m.emptyKdfInput == "fallback" && m.netName != "" {
			sess.Warnf("using eap.aka_prime.net_name %q in place of the empty AT_KDF_INPUT", m.netName)
			return m.netName, nil
		}
		return "", m.authenticationReject(req)
	}
	if m.netNameCheck != "off" && m.netName != "" && !netNameMatches(netName, m.netName) {
		sess.Warnf("AT_KDF_INPUT %q does not match eap.aka_prime.net_name %q", netName, m.netName)
		if m.netNameCheck == "reject" {
			return "", m.authenticationReject(req)
		}
	}
	return netName, nil
}

// netNameMatches はネットワーク名をコロン区切りのフィールドごとに比べる。
// フィールド数の少ない方に合わせて、先頭から比べる（RFC 9048 §3.1）。
func netNameMatches(a, b string) bool {
	fa, fb := strings.Split(a, ":"), strings.Split(b, ":")
	for i := range min(len(fa), len(fb)) {
		if fa[i] != fb[i] {
			return false
		}
	}
	return true
}

func (m *Method) computeVectors(rand []byte) ([]byte, []byte, []byte, []byte, error) {
	mil := milenage.NewWithOPc(m.ki, m.opc, rand, 0, m.amf)
	return mil.F2345()
}

// deriveKeys はフル認証の鍵を導出する（RFC 4187 §7、RFC 9048 §3.3）。
func (m *Method) deriveKeys(identity string, ck, ik []byte, netName string, autn []byte) (sessionKeys, error) {
	if m.methodType == eap.TypeAKA {
		k := eapaka.DeriveKeysAKA(identity, ck, ik)
		return sessionKeys{kEncr: k.K_encr, kAut: k.K_aut, msk: k.MSK, emsk: k.EMSK, mk: k.MK}, nil
	}
	ckPrime, ikPrime, err := eapaka.DeriveCKPrimeIKPrime(ck, ik, netName, autn)
	if err != nil {
		return sessionKeys{}, err
	}
	k := eapaka.DeriveKeysAKAPrime(identity, ckPrime, ikPrime)
	return sessionKeys{kEncr: k.K_encr, kAut: k.K_aut, msk: k.MSK, emsk: k.EMSK, kRe: k.K_re}, nil
}

func (m *Method) decodeAutn(autn, ak []byte) ([]byte, []byte, error) {
	if len(autn) != 16 {
		return nil, nil, fmt.Errorf("aka: invalid AUTN length")
	}
	if len(ak) != 6 {
		return nil, nil, fmt.Errorf("aka: invalid AK length")
	}
	sqn := make([]byte, 6)
	for i := range 6 {
		sqn[i] = autn[i] ^ ak[i]
	}
	amf := bytes.Clone(autn[6:8])
	return sqn, amf, nil
}

func (m *Method) verifyMacA(rand, sqn, amf, autn []byte) (bool, error) {
	mil := milenage.NewWithOPc(m.ki, m.opc, rand, 0, m.amf)
	copy(mil.SQN, sqn)
	copy(mil.AMF, amf)
	macA, err := mil.F1()
	if err != nil {
		return false, err
	}
	return bytes.Equal(macA, autn[8:16]), nil
}

func (m *Method) amfBytes() []byte {
	return []byte{byte(m.amf >> 8), byte(m.amf)}
}

// hasAttr は、パケットに型 T の属性があるかを返す。
func hasAttr[T eapaka.Attribute](p *eapaka.Packet) bool {
	for _, a := range p.Attributes {
		if _, ok := a.(T); ok {
			return true
		}
	}
	return false
}
