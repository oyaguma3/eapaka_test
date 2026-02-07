package app

import (
	"strings"
	"testing"

	"github.com/oyaguma3/eapaka_test/radiusc"
	"github.com/oyaguma3/eapaka_test/testcase"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func boolPtr(v bool) *bool {
	return &v
}

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

func TestRejectHintMissingReplyMessageDefaultFails(t *testing.T) {
	packet := radius.New(radius.CodeAccessReject, []byte("secret"))
	resp := &radiusc.Response{Code: radius.CodeAccessReject, Packet: packet}
	caseData := testcase.Case{Expect: testcase.Expect{Result: "reject", RejectHintContains: "not allowed"}}

	exitCode, err := evaluateExpect(caseData, resp, false)
	if err == nil {
		t.Fatalf("expected error for missing Reply-Message")
	}
	if exitCode != 1 {
		t.Fatalf("expected fail exit code 1, got %d", exitCode)
	}
	if !strings.Contains(err.Error(), "missing Reply-Message") {
		t.Fatalf("expected missing Reply-Message error, got %v", err)
	}
}

func TestRejectHintMissingReplyMessageCanSkipPresenceCheck(t *testing.T) {
	packet := radius.New(radius.CodeAccessReject, []byte("secret"))
	resp := &radiusc.Response{Code: radius.CodeAccessReject, Packet: packet}
	caseData := testcase.Case{Expect: testcase.Expect{
		Result:                  "reject",
		RejectHintContains:      "not allowed",
		RejectHintCheckPresence: boolPtr(false),
	}}

	exitCode, err := evaluateExpect(caseData, resp, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected pass when presence check is disabled")
	}
}

func TestRejectHintMismatchFailsEvenWhenPresenceCheckDisabled(t *testing.T) {
	packet := radius.New(radius.CodeAccessReject, []byte("secret"))
	_ = rfc2865.ReplyMessage_SetString(packet, "invalid credentials")
	resp := &radiusc.Response{Code: radius.CodeAccessReject, Packet: packet}
	caseData := testcase.Case{Expect: testcase.Expect{
		Result:                  "reject",
		RejectHintContains:      "not allowed",
		RejectHintCheckPresence: boolPtr(false),
	}}

	exitCode, err := evaluateExpect(caseData, resp, false)
	if err == nil {
		t.Fatalf("expected mismatch error")
	}
	if exitCode != 1 {
		t.Fatalf("expected fail exit code 1, got %d", exitCode)
	}
	if !strings.Contains(err.Error(), "reject_hint_contains mismatch") {
		t.Fatalf("expected mismatch error, got %v", err)
	}
}
