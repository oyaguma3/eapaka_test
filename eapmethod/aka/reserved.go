package aka

import (
	"encoding/binary"

	"github.com/oyaguma3/eapaka_test/eap"

	eapaka "github.com/oyaguma3/go-eapaka"
)

// reservedAttrs は、値フィールドの先頭 2 バイトが Reserved の属性（RFC 4187 §10）。
// AT_NONCE_S と AT_COUNTER_TOO_SMALL も Reserved を持つが、AT_ENCR_DATA の中にあり、
// 復号した結果は解析済みの形でしか得られないので、ここでは調べない。
var reservedAttrs = map[eapaka.AttributeType]string{
	eapaka.AT_RAND:             "AT_RAND",
	eapaka.AT_AUTN:             "AT_AUTN",
	eapaka.AT_PERMANENT_ID_REQ: "AT_PERMANENT_ID_REQ",
	eapaka.AT_MAC:              "AT_MAC",
	eapaka.AT_ANY_ID_REQ:       "AT_ANY_ID_REQ",
	eapaka.AT_FULLAUTH_ID_REQ:  "AT_FULLAUTH_ID_REQ",
	eapaka.AT_IV:               "AT_IV",
	eapaka.AT_ENCR_DATA:        "AT_ENCR_DATA",
	eapaka.AT_CHECKCODE:        "AT_CHECKCODE",
	eapaka.AT_RESULT_IND:       "AT_RESULT_IND",
}

// checkReserved は、受信した EAP-AKA/AKA' の要求の Reserved が 0 かを調べる（規則 A-15）。
// RFC 4187 は「送信時は 0、受信時は無視」としているので、違反があっても処理は続ける。
// MAC は受信したバイト列のまま検証するので、ここでの違反は認証の結果に影響しない。
func checkReserved(raw []byte, sess *eap.Session) {
	if len(raw) < 8 {
		return
	}
	rec := sess.Conformance
	// EAP-AKA ヘッダ: Code, Identifier, Length(2), Type, Subtype, Reserved(2)（§8.1）
	if raw[6] != 0 || raw[7] != 0 {
		rec.Report("A-15", "EAP-AKA header Reserved is %x", raw[6:8])
	}
	length := min(int(binary.BigEndian.Uint16(raw[2:4])), len(raw))
	for off := 8; off+4 <= length; {
		t, l := eapaka.AttributeType(raw[off]), int(raw[off+1])*4
		if l == 0 || off+l > length {
			return // 形式の誤りは解析の段階で扱う
		}
		if name, ok := reservedAttrs[t]; ok && (raw[off+2] != 0 || raw[off+3] != 0) {
			rec.Report("A-15", "%s Reserved is %x", name, raw[off+2:off+4])
		}
		if t == eapaka.AT_BIDDING && (raw[off+2]&0x7f != 0 || raw[off+3] != 0) {
			// AT_BIDDING は D ビット以外が Reserved（RFC 9048 §4）
			rec.Report("A-15", "AT_BIDDING reserved bits are %x", raw[off+2:off+4])
		}
		off += l
	}
}
