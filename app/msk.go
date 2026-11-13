package app

import (
	"bytes"
	"crypto/subtle"
	"slices"

	"github.com/oyaguma3/eapaka_test/eap"
	"github.com/oyaguma3/eapaka_test/radiusc"
	"github.com/oyaguma3/eapaka_test/testcase"
)

// verifyMSK は Access-Accept の MS-MPPE 鍵を復号し、ピアの MSK と比べる（X2、設計書 §6.2）。
// 結果は sess.Obs.MSKMatch と sess.Obs.MSKDetail に入れる。
func verifyMSK(sess *eap.Session, resp *radiusc.Response, secret, mapping string) {
	obs := &sess.Obs
	if len(sess.MSK) != 64 {
		obs.MSKDetail = "the peer has not derived an MSK"
		return
	}
	match := false
	obs.MSKMatch = &match
	send, recv, err := radiusc.DecryptMPPEKeys(resp.MPPE, []byte(secret), resp.RequestAuthenticator)
	if err != nil {
		obs.MSKDetail = err.Error()
		return
	}
	wantRecv, wantSend := sess.MSK[:32], sess.MSK[32:]
	if mapping == "swapped" {
		wantRecv, wantSend = wantSend, wantRecv
	}
	recvOK := subtle.ConstantTimeCompare(recv, wantRecv) == 1
	sendOK := subtle.ConstantTimeCompare(send, wantSend) == 1
	switch {
	case recvOK && sendOK:
		match = true
	case bytes.Equal(recv, wantSend) && bytes.Equal(send, wantRecv):
		obs.MSKDetail = "MS-MPPE keys match the MSK with Send and Recv swapped; check mppe.mapping"
	case !recvOK && !sendOK:
		obs.MSKDetail = "neither MS-MPPE-Recv-Key nor MS-MPPE-Send-Key matches the MSK"
	case !recvOK:
		obs.MSKDetail = "MS-MPPE-Recv-Key does not match the MSK"
	default:
		obs.MSKDetail = "MS-MPPE-Send-Key does not match the MSK"
	}
}

// evaluateBidding は expect.bidding を判定する（RFC 9048 §4）。
func evaluateBidding(tc testcase.Case, obs eap.Observations) (int, error) {
	e := tc.Expect.Bidding
	b := obs.Bidding
	if e.Present != nil && *e.Present != (b != nil) {
		return fail(1, "expect.bidding.present=%t but AT_BIDDING was %s", *e.Present, map[bool]string{true: "received", false: "not received"}[b != nil])
	}
	if e.DBit != nil && (b == nil || b.DBit != *e.DBit) {
		return fail(1, "expect.bidding.d_bit=%t does not match the received AT_BIDDING", *e.DBit)
	}
	if e.Action != "" && (b == nil || b.Action != e.Action) {
		return fail(1, "expect.bidding.action=%s does not match the peer's action", e.Action)
	}
	return 0, nil
}

// evaluateNotification は expect.notification を判定する。
func evaluateNotification(tc testcase.Case, obs eap.Observations) (int, error) {
	e := tc.Expect.Notification
	if e.Present != nil && *e.Present != (len(obs.Notifications) > 0) {
		return fail(1, "expect.notification.present=%t but %d AKA-Notification(s) were received", *e.Present, len(obs.Notifications))
	}
	if e.Code != nil && !slices.ContainsFunc(obs.Notifications, func(n eap.NotificationObs) bool { return n.Code == *e.Code }) {
		return fail(1, "expect.notification.code=%d was not received (received %v)", *e.Code, obs.Notifications)
	}
	return 0, nil
}

// evaluateMSK は expect.mppe.verify_msk を判定する。
func evaluateMSK(tc testcase.Case, obs eap.Observations) (int, error) {
	if !tc.Expect.MPPE.VerifyMSK {
		return 0, nil
	}
	if obs.MSKMatch == nil || !*obs.MSKMatch {
		return fail(1, "expect.mppe.verify_msk: %s", obs.MSKDetail)
	}
	return 0, nil
}
