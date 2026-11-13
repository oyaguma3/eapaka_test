package aka

import (
	"github.com/oyaguma3/eapaka_test/eap"

	eapaka "github.com/oyaguma3/go-eapaka"
)

// Fault は、ピアがわざと違反する異常系の注入（設計書 §6.4、X4）。
// 組み合わせの検証は testcase パッケージで行う。
type Fault struct {
	At     string // 注入位置（FaultAt*）
	Action string // 動作（Fault*）
}

// 注入位置
const (
	FaultAtIdentityResponse  = "identity_response"
	FaultAtChallengeResponse = "challenge_response"
)

// 動作
const (
	FaultCorruptMAC  = "corrupt_mac"  // 応答の AT_MAC を壊す
	FaultWrongRES    = "wrong_res"    // 誤った AT_RES を正しい MAC で送る
	FaultClientError = "client_error" // 応答を Client-Error に差し替える
	FaultAuthReject  = "auth_reject"  // 応答を Authentication-Reject に差し替える
)

// faultAt は注入位置 at に指定された動作を返す（最初に一致したものだけ）。
// 注入したことは観測結果とトレースに残す。
func (m *Method) faultAt(at string, sess *eap.Session) string {
	for _, f := range m.faults {
		if f.At == at {
			sess.Obs.Faults = append(sess.Obs.Faults, at+"/"+f.Action)
			sess.Warnf("fault injected at=%s action=%s", at, f.Action)
			return f.Action
		}
	}
	return ""
}

// replaceByFault は、応答を差し替える動作なら、差し替えた応答を返す（ok が true）。
func (m *Method) replaceByFault(action string, req *eapaka.Packet) (resp *eap.Packet, ok bool, err error) {
	switch action {
	case FaultClientError:
		resp, err = m.clientError(req)
		return resp, true, err
	case FaultAuthReject:
		return m.authenticationReject(req), true, nil
	default:
		return nil, false, nil
	}
}
