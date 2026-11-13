package aka

import (
	"errors"

	"github.com/oyaguma3/eapaka_test/eap"

	eapaka "github.com/oyaguma3/go-eapaka"
)

// handleNotification は EAP-Request/AKA-Notification を処理する（RFC 4187 §6、§9.10・§9.11）。
// コードを知らなくても応答する（§6.1）。
func (m *Method) handleNotification(req *eapaka.Packet, raw []byte, sess *eap.Session) (*eap.Packet, error) {
	rec := sess.Conformance
	var n *eapaka.AtNotification
	for _, a := range req.Attributes {
		if v, ok := a.(*eapaka.AtNotification); ok {
			n = v
		}
	}
	if n == nil {
		rec.Report("A-16", "AKA-Notification lacks AT_NOTIFICATION")
		return m.clientError(req)
	}
	code := n.FullCode()
	sess.Obs.Notifications = append(sess.Obs.Notifications, eap.NotificationObs{Code: code, S: n.S, P: n.P})
	sess.Warnf("AKA-Notification received: code=%d S=%t P=%t", code, n.S, n.P)

	m.s.notifications++
	if m.s.notifications > 1 {
		rec.Report("A-08", "AKA-Notification round %d in one EAP exchange (only one is allowed)", m.s.notifications)
	}
	if n.P && n.S {
		rec.Report("A-08", "AKA-Notification code %d has both the P and S bits set", code)
	}

	resp := &eapaka.Packet{
		Code:       eapaka.CodeResponse,
		Identifier: req.Identifier,
		Type:       req.Type,
		Subtype:    eapaka.SubtypeNotification,
	}

	if n.P {
		// 認証前の通知（P=1）。AT_MAC なしの空の Notification で応答する（§9.11）
		if !n.S {
			m.s.phase = phaseFailed
		}
		return toEAPPacket(resp)
	}

	// 認証後の通知（P=0）。Challenge が成功した後だけ使える（§6.1）
	if m.s.phase != phaseChallenged && m.s.phase != phaseAwaitingResult {
		rec.Report("A-08", "AKA-Notification with P=0 (code %d) before successful authentication", code)
		return m.clientError(req)
	}
	ok, err := eapaka.VerifyMacRaw(raw, m.s.keys.kAut, nil)
	switch {
	case errors.Is(err, eapaka.ErrMacNotFound):
		rec.Report("A-18", "AKA-Notification with P=0 lacks AT_MAC")
		return m.clientError(req)
	case err != nil || !ok:
		rec.Report("A-18", "AKA-Notification AT_MAC is invalid")
		return m.clientError(req)
	}
	switch {
	case n.S && !m.s.resultInd:
		// 成功通知は、双方が AT_RESULT_IND を使ったときだけ送れる（§6.2）
		rec.Report("A-08", "success AKA-Notification (code %d) although AT_RESULT_IND was not used", code)
		m.s.phase = phaseChallenged
	case n.S:
		m.s.phase = phaseChallenged
	default:
		// 認証後の失敗通知。この後に成功を受け入れてはならない（§6.3.4）
		m.s.phase = phaseFailed
	}
	resp.Attributes = []eapaka.Attribute{&eapaka.AtMac{MAC: make([]byte, 16)}}
	if err := resp.CalculateAndSetMac(m.s.keys.kAut); err != nil {
		return nil, err
	}
	return toEAPPacket(resp)
}
