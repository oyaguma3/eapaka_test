package aka

import (
	"errors"
	"strings"

	"github.com/oyaguma3/eapaka_test/eap"
	"github.com/oyaguma3/eapaka_test/idstore"

	eapaka "github.com/oyaguma3/go-eapaka"
)

// processEncrData は Challenge の AT_ENCR_DATA を復号し、次回の仮名などを取り出す
// （RFC 4187 §10.12、設計書 §5.3）。AT_MAC を検証した後に呼ぶ。
// 処理を続けられないときは、返すべき応答（Client-Error）を resp に入れて done を true にする。
func (m *Method) processEncrData(req *eapaka.Packet, kEncr []byte, sess *eap.Session) (resp *eap.Packet, done bool, err error) {
	rec := sess.Conformance
	var iv, enc []byte
	for _, a := range req.Attributes {
		switch v := a.(type) {
		case *eapaka.AtIv:
			iv = v.IV
		case *eapaka.AtEncrData:
			enc = v.EncryptedData
		case *eapaka.AtNextPseudonym, *eapaka.AtNextReauthId:
			rec.Report("A-06", "attribute %d is sent unencrypted", a.Type())
		}
	}
	if enc == nil {
		return nil, false, nil
	}
	if len(iv) != 16 {
		rec.Report("A-16", "AT_ENCR_DATA without a valid AT_IV")
		resp, err = m.clientError(req)
		return resp, true, err
	}
	m.recordIV(iv, req.Type, sess)

	attrs, err := eapaka.DecryptAttributes(kEncr, iv, enc)
	if err != nil {
		rule := "A-16"
		for _, target := range []error{eapaka.ErrEncrDataLength, eapaka.ErrPaddingLength, eapaka.ErrPaddingNotZero, eapaka.ErrPaddingNotLast} {
			if errors.Is(err, target) {
				rule = "A-05"
			}
		}
		rec.Report(rule, "AT_ENCR_DATA cannot be decrypted: %v", err)
		resp, err = m.clientError(req)
		return resp, true, err
	}
	for _, a := range attrs {
		switch v := a.(type) {
		case *eapaka.GenericAttribute:
			if !eapaka.IsSkippable(v.AttrType) {
				rec.Report("A-16", "unknown non-skippable attribute %d in AT_ENCR_DATA", v.AttrType)
				resp, err = m.clientError(req)
				return resp, true, err
			}
		case *eapaka.AtResultInd:
			rec.Report("A-07", "AT_RESULT_IND is inside AT_ENCR_DATA")
		case *eapaka.AtNextPseudonym:
			m.receivePseudonym(v.Pseudonym, req.Type, sess)
		case *eapaka.AtNextReauthId:
			// 再認証 ID の保存と利用は Phase 5 で扱う
			sess.Obs.NextReauthID = true
		}
	}
	return nil, false, nil
}

// receivePseudonym は AT_NEXT_PSEUDONYM を検査し、認証が成功したら保存するように置いておく。
// 受け取った仮名は書き換えない（RFC 4187 §4.1.1.9）。
func (m *Method) receivePseudonym(p string, methodType uint8, sess *eap.Session) {
	rec := sess.Conformance
	sess.Obs.NextPseudonym = true
	if strings.Contains(p, "@") {
		// RFC 4187 §10.10: AT_NEXT_PSEUDONYM にはレルムを含めない
		rec.Report("A-06", "AT_NEXT_PSEUDONYM %q includes a realm", maskID(p))
	}
	if methodType == eap.TypeAKAPrime && revealsIMSI(p, m.imsi) {
		rec.Report("A-14", "EAP-AKA' pseudonym %q appears to contain the IMSI", maskID(p))
	}
	sess.Pending = eap.PendingIDs{Method: methodType, Pseudonym: p}
}

// recordIV は AT_IV を履歴と比べて、再利用なら A-02 として記録する（実行をまたいでも調べる）。
func (m *Method) recordIV(iv []byte, methodType uint8, sess *eap.Session) {
	if m.idstore == nil {
		return
	}
	method := idstore.MethodFor(methodType)
	entry, err := m.idstore.Get(m.imsi, method)
	if err != nil {
		sess.Warnf("identity store: %v", err)
		return
	}
	if entry.AddIV(iv) {
		sess.Conformance.Report("A-02", "AT_IV was used before (within the last %d IVs)", idstore.HistoryLimit)
	}
	if err := m.idstore.Put(m.imsi, method, entry); err != nil {
		sess.Warnf("identity store: %v", err)
	}
}

// revealsIMSI は、仮名に IMSI か MSIN（末尾 9 桁）が含まれているかを推定する（A-14）。
func revealsIMSI(pseudonym, imsi string) bool {
	if imsi == "" {
		return false
	}
	if strings.Contains(pseudonym, imsi) {
		return true
	}
	return len(imsi) >= 9 && strings.Contains(pseudonym, imsi[len(imsi)-9:])
}

// maskID は、違反の記録に出す識別子の中ほどを伏せる。
func maskID(s string) string {
	if len(s) <= 4 {
		return "***"
	}
	return s[:2] + "***" + s[len(s)-2:]
}
