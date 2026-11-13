package app

import (
	"bytes"
	"fmt"

	"github.com/oyaguma3/eapaka_test/conformance"
	"github.com/oyaguma3/eapaka_test/eap"
	"github.com/oyaguma3/eapaka_test/radiusc"

	"layeh.com/radius"
)

// checkResponse は RADIUS 応答に対して RADIUS/EAP 層の規則（R-01〜R-05、R-07、A-10）を検査する。
// lastRespID は直前に送った EAP-Response の Identifier、obs はその時点の観測結果。
func checkResponse(rec *conformance.Recorder, resp *radiusc.Response, lastRespID uint8, obs eap.Observations) {
	method := obs.Method
	if resp.MessageAuthenticatorPresent && !resp.MessageAuthenticatorValid {
		rec.Report("R-01", "%s has an invalid Message-Authenticator", resp.Code)
	}
	if len(resp.EAP) > 0 && !resp.MessageAuthenticatorPresent {
		rec.Report("R-02", "%s carries EAP-Message without Message-Authenticator", resp.Code)
	}

	var pkt *eap.Packet
	if len(resp.EAP) > 0 {
		if p, err := eap.Parse(resp.EAP); err == nil {
			pkt = &p
		}
	}
	switch resp.Code {
	case radius.CodeAccessChallenge:
		if pkt == nil || pkt.Code != eap.CodeRequest {
			rec.Report("R-03b", "Access-Challenge carries %s instead of an EAP-Request", describeEAP(pkt, resp.EAP))
		} else if obs.PeerError && pkt.Type != eap.TypeNotify {
			// RFC 4187 §6.3.1: ピアの Client-Error / Authentication-Reject の後は EAP-Failure を送る
			rec.Report("A-10", "EAP-Request type %d received after the peer sent Client-Error or Authentication-Reject", pkt.Type)
		}
	case radius.CodeAccessAccept:
		if pkt == nil || pkt.Code != eap.CodeSuccess {
			rec.Report("R-03a", "Access-Accept carries %s instead of EAP-Success", describeEAP(pkt, resp.EAP))
		}
		if method != eap.MethodCompleted {
			rec.Report("R-05", "Access-Accept received while the EAP method is %s%s", method, prematureReason(obs))
		}
		checkMPPESalts(rec, resp.MPPE)
	case radius.CodeAccessReject:
		if pkt == nil || pkt.Code != eap.CodeFailure {
			rec.Report("R-03a", "Access-Reject carries %s instead of EAP-Failure", describeEAP(pkt, resp.EAP))
		}
	}

	if pkt == nil || (pkt.Code != eap.CodeSuccess && pkt.Code != eap.CodeFailure) {
		return
	}
	if pkt.Identifier != lastRespID {
		rec.Report("R-04", "%s Identifier %d does not match the last EAP-Response Identifier %d",
			eapCodeName(pkt.Code), pkt.Identifier, lastRespID)
	}
	// Access-Accept の場合は上で R-05 を報告済み
	if pkt.Code == eap.CodeSuccess && resp.Code != radius.CodeAccessAccept && method != eap.MethodCompleted {
		rec.Report("R-05", "EAP-Success received in %s while the EAP method is %s", resp.Code, method)
	}
}

// checkMPPESalts は MS-MPPE 鍵の Salt を検査する（R-07、RFC 2548 §2.4.2）。
func checkMPPESalts(rec *conformance.Recorder, keys radiusc.MPPEKeys) {
	var salts [][]byte
	for _, k := range []struct {
		name    string
		present bool
		value   []byte
	}{
		{"MS-MPPE-Send-Key", keys.SendKeyPresent, keys.SendKey},
		{"MS-MPPE-Recv-Key", keys.RecvKeyPresent, keys.RecvKey},
	} {
		if !k.present {
			continue
		}
		if len(k.value) < 2 {
			rec.Report("R-07", "%s is too short to hold a Salt", k.name)
			continue
		}
		if k.value[0]&0x80 == 0 {
			rec.Report("R-07", "%s Salt %x does not have the most significant bit set", k.name, k.value[:2])
		}
		salts = append(salts, k.value[:2])
	}
	if len(salts) == 2 && bytes.Equal(salts[0], salts[1]) {
		rec.Report("R-07", "MS-MPPE-Send-Key and MS-MPPE-Recv-Key share the Salt %x", salts[0])
	}
}

// prematureReason は、成功が早すぎる理由を補足する（RFC 4187 §6.3.4）。
func prematureReason(obs eap.Observations) string {
	switch {
	case obs.FailureNotified():
		return " (after a failure notification)"
	case obs.ResultInd && !obs.SuccessNotified():
		return " (AT_RESULT_IND was used but no success notification was received)"
	case obs.PeerError:
		return " (after the peer's Client-Error or Authentication-Reject)"
	default:
		return ""
	}
}

func describeEAP(pkt *eap.Packet, raw []byte) string {
	switch {
	case len(raw) == 0:
		return "no EAP-Message"
	case pkt == nil:
		return "a malformed EAP packet"
	default:
		return eapCodeName(pkt.Code)
	}
}

func eapCodeName(code uint8) string {
	switch code {
	case eap.CodeRequest:
		return "EAP-Request"
	case eap.CodeResponse:
		return "EAP-Response"
	case eap.CodeSuccess:
		return "EAP-Success"
	case eap.CodeFailure:
		return "EAP-Failure"
	default:
		return fmt.Sprintf("EAP code %d", code)
	}
}
