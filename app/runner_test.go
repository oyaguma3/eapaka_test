package app

import (
	"testing"

	"github.com/oyaguma3/eapaka_test/radiusc"
	"github.com/oyaguma3/eapaka_test/testcase"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func TestRejectHintContains(t *testing.T) {
	packet := radius.New(radius.CodeAccessReject, []byte("secret"))
	_ = rfc2865.ReplyMessage_SetString(packet, "user not allowed")
	resp := &radiusc.Response{Code: radius.CodeAccessReject, Packet: packet}
	caseData := testcase.Case{Expect: testcase.Expect{Result: "reject", RejectHintContains: "not allowed"}}

	exitCode, err := evaluateExpect(caseData, resp, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected pass for matching reject hint")
	}
}
