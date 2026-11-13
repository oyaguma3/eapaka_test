package aka

import (
	"errors"

	"github.com/oyaguma3/eapaka_test/eap"
	"github.com/oyaguma3/eapaka_test/idstore"

	eapaka "github.com/oyaguma3/go-eapaka"
)

// handleReauth は EAP-Request/AKA-Reauthentication を処理する（RFC 4187 §5・§9.7・§9.8、設計書 §5.4）。
func (m *Method) handleReauth(req *eapaka.Packet, raw []byte, sess *eap.Session) (*eap.Packet, error) {
	rec := sess.Conformance
	ctx := m.reauthCtx
	if ctx == nil {
		sess.Warnf("no fast re-authentication context for EAP type %d; answering Client-Error", req.Type)
		return m.clientError(req)
	}
	// 1. AT_MAC（追加データなし、§9.7）
	if ok, err := eapaka.VerifyMacRaw(raw, ctx.KAut, nil); err != nil || !ok {
		rec.Report("A-18", "AKA-Reauthentication AT_MAC is missing or invalid")
		return m.clientError(req)
	}
	// 2. AT_ENCR_DATA から AT_COUNTER・AT_NONCE_S・AT_NEXT_REAUTH_ID を取り出す
	inner, resp, err := m.decryptReauthAttrs(req, ctx.KEncr, sess)
	if resp != nil || err != nil {
		return resp, err
	}
	var counter *uint16
	var nonceS []byte
	var nextReauthID string
	for _, a := range inner {
		switch v := a.(type) {
		case *eapaka.AtCounter:
			counter = &v.Counter
		case *eapaka.AtNonceS:
			nonceS = v.NonceS
		case *eapaka.AtNextReauthId:
			nextReauthID = v.Identity
		case *eapaka.AtNextPseudonym:
			// RFC 4187 表 10.1: AT_NEXT_PSEUDONYM は再認証の要求には入れない
			rec.Report("A-06", "AT_NEXT_PSEUDONYM in AKA-Reauthentication")
		}
	}
	if counter == nil || len(nonceS) != 16 {
		rec.Report("A-16", "AKA-Reauthentication lacks AT_COUNTER or AT_NONCE_S")
		return m.clientError(req)
	}
	m.recordNonceS(nonceS, req.Type, sess)

	// 3. AT_COUNTER の確認（§5.4、§5.5）
	action := m.faultAt(FaultAtReauthResponse, sess)
	if *counter < ctx.CounterFloor {
		rec.Report("A-04", "AT_COUNTER %d is lower than the expected minimum %d", *counter, ctx.CounterFloor)
	}
	if *counter < ctx.CounterFloor || action == FaultCounterTooSmall {
		return m.counterTooSmall(req, *counter, nonceS, ctx, sess)
	}
	if resp, ok, err := m.replaceByFault(action, req); ok {
		return resp, err
	}

	// 4. 鍵の導出。作り直すのは MSK・EMSK だけで、K_encr と K_aut はフル認証のものを使う（§7）
	identity := sess.InnerIdentity
	if identity == "" {
		identity = sess.OuterIdentity
	}
	var rk eapaka.ReauthKeys
	if req.Type == eapaka.TypeAKA {
		rk, err = eapaka.DeriveReauthKeysAKA(identity, *counter, nonceS, ctx.MK)
	} else {
		rk, err = eapaka.DeriveReauthKeysAKAPrime(identity, *counter, nonceS, ctx.KRe)
	}
	if err != nil {
		return nil, err
	}

	// 5. 応答: AT_IV、AT_ENCR_DATA{AT_COUNTER}、AT_MAC（EAP パケット | NONCE_S、§9.8）
	respCounter := *counter
	if action == FaultWrongCounter {
		respCounter++
	}
	attrs, err := m.encryptedCounter(ctx.KEncr, &eapaka.AtCounter{Counter: respCounter})
	if err != nil {
		return nil, err
	}
	useResultInd := m.resultInd && hasAttr[*eapaka.AtResultInd](req)
	if useResultInd {
		attrs = append(attrs, &eapaka.AtResultInd{})
	}
	ccValue, ccInclude, ccResp, err := m.checkcode(req, sess)
	if ccResp != nil || err != nil {
		return ccResp, err
	}
	if ccInclude {
		attrs = append(attrs, &eapaka.AtCheckcode{Checkcode: ccValue})
	}
	mac := &eapaka.AtMac{MAC: make([]byte, 16)}
	out := &eapaka.Packet{
		Code: eapaka.CodeResponse, Identifier: req.Identifier, Type: req.Type,
		Subtype: eapaka.SubtypeReauthentication, Attributes: append(attrs, mac),
	}
	if err := out.CalculateAndSetMacWithExtra(ctx.KAut, nonceS); err != nil {
		return nil, err
	}

	m.s.keys = sessionKeys{kEncr: ctx.KEncr, kAut: ctx.KAut, msk: rk.MSK, emsk: rk.EMSK, mk: ctx.MK, kRe: ctx.KRe}
	m.s.reauthed, m.s.counter = true, *counter
	sess.MSK = rk.MSK
	sess.Obs.AuthType, sess.Obs.ReauthCounter = "reauth", *counter
	m.s.phase = phaseChallenged
	if useResultInd {
		m.s.resultInd = true
		m.s.phase = phaseAwaitingResult
	}
	switch action {
	case FaultCorruptMAC:
		mac.MAC[len(mac.MAC)-1] ^= 0xff
		fallthrough
	case FaultWrongCounter:
		// 応答が無効なので、サーバは成功を返してはならない（返せば R-05 で検出する）
		m.s.phase = phaseFailed
	}

	// 6. 次回の再認証コンテキスト。AT_NEXT_REAUTH_ID がなければ再認証の状態を破棄する（§5.3）
	sess.Pending.Method, sess.Pending.AuthDone, sess.Pending.Reauth = req.Type, true, nil
	if nextReauthID != "" {
		sess.Obs.NextReauthID = true
		next := *ctx
		next.Identity, next.CounterFloor = nextReauthID, *counter+1
		sess.Pending.Reauth = &next
	}
	return toEAPPacket(out)
}

// counterTooSmall は AT_COUNTER_TOO_SMALL で応答する（§5.5）。鍵は導出せず、AT_NEXT_REAUTH_ID は無視する。
// サーバはこの後、AKA-Identity を挟まずにフル認証の Challenge を送ってくる（規則 A-11）。
func (m *Method) counterTooSmall(req *eapaka.Packet, counter uint16, nonceS []byte, ctx *idstore.Reauth, sess *eap.Session) (*eap.Packet, error) {
	attrs, err := m.encryptedCounter(ctx.KEncr, &eapaka.AtCounter{Counter: counter}, &eapaka.AtCounterTooSmall{})
	if err != nil {
		return nil, err
	}
	out := &eapaka.Packet{
		Code: eapaka.CodeResponse, Identifier: req.Identifier, Type: req.Type,
		Subtype: eapaka.SubtypeReauthentication, Attributes: append(attrs, &eapaka.AtMac{MAC: make([]byte, 16)}),
	}
	if err := out.CalculateAndSetMacWithExtra(ctx.KAut, nonceS); err != nil {
		return nil, err
	}
	m.s.counterTooSmallSent = true
	sess.Obs.CounterTooSmallSent = true
	return toEAPPacket(out)
}

// encryptedCounter は、属性を新しい AT_IV で暗号化した AT_IV と AT_ENCR_DATA を返す。
func (m *Method) encryptedCounter(kEncr []byte, inner ...eapaka.Attribute) ([]eapaka.Attribute, error) {
	iv := eapaka.NewIV()
	enc, err := eapaka.EncryptAttributes(kEncr, iv, inner)
	if err != nil {
		return nil, err
	}
	return []eapaka.Attribute{&eapaka.AtIv{IV: iv}, &eapaka.AtEncrData{EncryptedData: enc}}, nil
}

// decryptReauthAttrs は、再認証の要求や再認証の後の通知の AT_ENCR_DATA を復号する。
// 続けられないときは Client-Error を resp に入れる。
func (m *Method) decryptReauthAttrs(req *eapaka.Packet, kEncr []byte, sess *eap.Session) (attrs []eapaka.Attribute, resp *eap.Packet, err error) {
	rec := sess.Conformance
	var iv, enc []byte
	for _, a := range req.Attributes {
		switch v := a.(type) {
		case *eapaka.AtIv:
			iv = v.IV
		case *eapaka.AtEncrData:
			enc = v.EncryptedData
		case *eapaka.AtCounter, *eapaka.AtNonceS, *eapaka.AtNextReauthId, *eapaka.AtNextPseudonym:
			// RFC 4187 表 10.1: これらは暗号化して送る
			rec.Report("A-06", "attribute %d is sent unencrypted", a.Type())
		}
	}
	if len(iv) != 16 || enc == nil {
		rec.Report("A-16", "subtype %d lacks AT_IV or AT_ENCR_DATA", req.Subtype)
		resp, err = m.clientError(req)
		return nil, resp, err
	}
	m.recordIV(iv, req.Type, sess)
	attrs, err = eapaka.DecryptAttributes(kEncr, iv, enc)
	if err != nil {
		rule := "A-16"
		for _, target := range []error{eapaka.ErrEncrDataLength, eapaka.ErrPaddingLength, eapaka.ErrPaddingNotZero, eapaka.ErrPaddingNotLast} {
			if errors.Is(err, target) {
				rule = "A-05"
			}
		}
		rec.Report(rule, "AT_ENCR_DATA cannot be decrypted: %v", err)
		resp, err = m.clientError(req)
		return nil, resp, err
	}
	for _, a := range attrs {
		switch v := a.(type) {
		case *eapaka.GenericAttribute:
			if !eapaka.IsSkippable(v.AttrType) {
				rec.Report("A-16", "unknown non-skippable attribute %d in AT_ENCR_DATA", v.AttrType)
				resp, err = m.clientError(req)
				return nil, resp, err
			}
		case *eapaka.AtResultInd:
			rec.Report("A-07", "AT_RESULT_IND is inside AT_ENCR_DATA")
		}
	}
	return attrs, nil, nil
}

// recordNonceS は AT_NONCE_S を履歴と比べて、再利用なら A-03 として記録する（実行をまたいでも調べる）。
func (m *Method) recordNonceS(nonce []byte, methodType uint8, sess *eap.Session) {
	if m.idstore == nil {
		return
	}
	method := idstore.MethodFor(methodType)
	entry, err := m.idstore.Get(m.imsi, method)
	if err != nil {
		sess.Warnf("identity store: %v", err)
		return
	}
	if entry.AddNonceS(nonce) {
		sess.Conformance.Report("A-03", "AT_NONCE_S was used before (within the last %d values)", idstore.HistoryLimit)
	}
	if err := m.idstore.Put(m.imsi, method, entry); err != nil {
		sess.Warnf("identity store: %v", err)
	}
}
