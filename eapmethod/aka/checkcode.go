package aka

import (
	"bytes"

	"github.com/oyaguma3/eapaka_test/eap"

	eapaka "github.com/oyaguma3/go-eapaka"
)

// checkcode は AT_CHECKCODE を検証し、応答に入れる値を返す（RFC 4187 §10.13、RFC 9048 §3.4.3）。
// include が false なら応答に入れない。一致しなければ Client-Error を resp に入れる。
func (m *Method) checkcode(req *eapaka.Packet, sess *eap.Session) (value []byte, include bool, resp *eap.Packet, err error) {
	var received *eapaka.AtCheckcode
	for _, a := range req.Attributes {
		if v, ok := a.(*eapaka.AtCheckcode); ok {
			received = v
		}
	}
	include = m.checkcodeMode == "always" || (m.checkcodeMode == "auto" && received != nil)
	if received == nil && !include {
		return nil, false, nil, nil
	}
	// AKA-Identity の Request / Response を送受信したままの形で順につないだもののハッシュ。
	// やりとりがなければ長さ 0
	value, err = eapaka.ComputeCheckcode(req.Type, m.s.identityMsgs...)
	if err != nil {
		return nil, false, nil, err
	}
	if received != nil {
		if bytes.Equal(received.Checkcode, value) {
			sess.Obs.Checkcode = "verified"
		} else {
			sess.Obs.Checkcode = "mismatch"
			sess.Conformance.Report("A-19", "AT_CHECKCODE (%d bytes) does not match the %d AKA-Identity messages", len(received.Checkcode), len(m.s.identityMsgs))
			resp, err = m.clientError(req)
			return nil, false, resp, err
		}
	}
	return value, include, nil, nil
}
