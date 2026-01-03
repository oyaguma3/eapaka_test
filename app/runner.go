package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/oyaguma3/eapaka_test/config"
	"github.com/oyaguma3/eapaka_test/eap"
	"github.com/oyaguma3/eapaka_test/radiusc"
	"github.com/oyaguma3/eapaka_test/sqnstore"
	"github.com/oyaguma3/eapaka_test/testcase"
	"github.com/oyaguma3/eapaka_test/trace"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

// RunError wraps an execution failure with its exit code.
type RunError struct {
	Code int
	Err  error
}

func (e *RunError) Error() string {
	return e.Err.Error()
}

func (e *RunError) Unwrap() error {
	return e.Err
}

// RunCase executes a single testcase and returns the exit code (0/1/2).
func RunCase(ctx context.Context, cfg config.Config, tc testcase.Case) (int, error) {
	merged := config.ApplyTestcase(cfg, tc)

	store, err := buildStore(merged, tc)
	if err != nil {
		return wrap(2, err, "build store")
	}
	if tc.SQN.Reset {
		if err := store.Reset(merged.SIM.IMSI); err != nil {
			return wrap(2, err, "sqn reset")
		}
	}

	peer, err := BuildPeer(cfg, tc, store)
	if err != nil {
		return wrap(2, err, "build peer")
	}
	if peer.Session == nil || peer.Session.OuterIdentity == "" {
		return fail(2, "outer identity is required")
	}

	attrs := radiusc.Attributes{
		NASIPAddress:     merged.RadiusAttrs.NASIPAddress,
		NASIdentifier:    merged.RadiusAttrs.NASIdentifier,
		CalledStationID:  merged.RadiusAttrs.CalledStationID,
		CallingStationID: merged.RadiusAttrs.CallingStationID,
	}

	client := radiusc.NewClient(
		merged.Radius.ServerAddr,
		merged.Radius.Secret,
		time.Duration(merged.Radius.TimeoutMS)*time.Millisecond,
		merged.Radius.Retries,
	)

	logger := buildLogger(tc)
	userName := peer.Session.OuterIdentity
	respPkt := &eap.Packet{
		Code:       eap.CodeResponse,
		Identifier: 0,
		Type:       eap.TypeIdentity,
		TypeData:   []byte(userName),
	}

	for {
		raw, err := respPkt.Encode()
		if err != nil {
			return wrap(2, err, "encode eap response")
		}
		resp, err := client.ExchangeEAP(ctx, userName, raw, attrs)
		if err != nil {
			return wrap(2, err, "radius exchange")
		}
		if logger != nil {
			logger.LogRadius(resp.Code, resp.Packet, resp.EAP, peer.Session)
		}

		switch resp.Code {
		case radius.CodeAccessChallenge:
			if len(resp.EAP) == 0 {
				return fail(2, "missing EAP-Message in Access-Challenge")
			}
			reqPkt, err := eap.Parse(resp.EAP)
			if err != nil {
				return wrap(2, err, "parse EAP request")
			}
			nextResp, err := peer.Handle(reqPkt)
			if err != nil {
				if _, ok := err.(*eap.MethodMismatchError); ok {
					return wrap(1, err, "method mismatch")
				}
				return wrap(2, err, "handle EAP request")
			}
			if nextResp == nil {
				return fail(2, "no response for challenge")
			}
			if logger != nil {
				logger.LogChallengeResponse(&reqPkt, nextResp, peer.Session)
			}
			respPkt = nextResp
			if peer.Session != nil && peer.Session.OuterIdentity != "" {
				userName = peer.Session.OuterIdentity
			}
		case radius.CodeAccessAccept:
			if logger != nil {
				logger.LogMPPE(resp.MPPE)
			}
			return evaluateExpect(tc, resp, true)
		case radius.CodeAccessReject:
			if logger != nil {
				logger.LogMPPE(resp.MPPE)
			}
			return evaluateExpect(tc, resp, false)
		default:
			return fail(2, "unexpected RADIUS code %d", resp.Code)
		}
	}
}

func buildStore(cfg config.Config, tc testcase.Case) (sqnstore.Store, error) {
	persist := true
	if tc.SQN.Persist != nil {
		persist = *tc.SQN.Persist
	}
	if !persist {
		return sqnstore.NewMemoryStore(), nil
	}
	switch cfg.SQNStore.Mode {
	case "memory":
		return sqnstore.NewMemoryStore(), nil
	case "file":
		if cfg.SQNStore.Path == "" {
			return nil, fmt.Errorf("sqn_store.path is required")
		}
		return &sqnstore.FileStore{Path: cfg.SQNStore.Path}, nil
	default:
		return nil, fmt.Errorf("unsupported sqn_store.mode %q", cfg.SQNStore.Mode)
	}
}

func evaluateExpect(tc testcase.Case, resp *radiusc.Response, accepted bool) (int, error) {
	expectedAccept := tc.Expect.Result == "accept"
	actual := "reject"
	if accepted {
		actual = "accept"
	}
	if accepted != expectedAccept {
		return fail(1, "expect result=%s got=%s", tc.Expect.Result, actual)
	}
	if !accepted && tc.Expect.RejectHintContains != "" {
		hint := rfc2865.ReplyMessage_GetString(resp.Packet)
		if hint == "" {
			return fail(1, "reject_hint_contains missing Reply-Message")
		}
		if !strings.Contains(hint, tc.Expect.RejectHintContains) {
			return fail(1, "reject_hint_contains mismatch: want %q got %q", tc.Expect.RejectHintContains, hint)
		}
	}

	requirePresent := expectedAccept
	if tc.Expect.MPPE.RequirePresent != nil {
		requirePresent = *tc.Expect.MPPE.RequirePresent
	}
	if requirePresent {
		if !resp.MPPE.SendKeyPresent || !resp.MPPE.RecvKeyPresent {
			return fail(1, "mppe keys missing")
		}
	}
	if tc.Expect.MPPE.SendKey != "" {
		value, err := decodeKey(tc.Expect.MPPE.SendKey)
		if err != nil {
			return wrap(2, err, "decode expect.mppe.send_key")
		}
		if !resp.MPPE.SendKeyPresent || !bytes.Equal(resp.MPPE.SendKey, value) {
			return fail(1, "mppe send_key mismatch")
		}
	}
	if tc.Expect.MPPE.RecvKey != "" {
		value, err := decodeKey(tc.Expect.MPPE.RecvKey)
		if err != nil {
			return wrap(2, err, "decode expect.mppe.recv_key")
		}
		if !resp.MPPE.RecvKeyPresent || !bytes.Equal(resp.MPPE.RecvKey, value) {
			return fail(1, "mppe recv_key mismatch")
		}
	}
	return 0, nil
}

func decodeKey(value string) ([]byte, error) {
	switch {
	case len(value) >= 4 && value[:4] == "hex:":
		return hex.DecodeString(value[4:])
	case len(value) >= 4 && value[:4] == "b64:":
		return base64.StdEncoding.DecodeString(value[4:])
	default:
		return nil, fmt.Errorf("unsupported key encoding")
	}
}

func buildLogger(tc testcase.Case) *trace.Logger {
	level := trace.LevelNormal
	if tc.Trace.Level == "verbose" {
		level = trace.LevelVerbose
	}
	dumpEAPHex := true
	if tc.Trace.DumpEAPHex != nil {
		dumpEAPHex = *tc.Trace.DumpEAPHex
	}
	dumpRadius := true
	if tc.Trace.DumpRadiusAttrs != nil {
		dumpRadius = *tc.Trace.DumpRadiusAttrs
	}
	out := os.Stderr
	if tc.Trace.SavePath != "" {
		file, err := os.OpenFile(tc.Trace.SavePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err == nil {
			out = file
		}
	}
	return &trace.Logger{
		Level:           level,
		Out:             out,
		Unsafe:          tc.Trace.UnsafeLog,
		DumpEAPHex:      dumpEAPHex,
		DumpRadiusAttrs: dumpRadius,
	}
}

func fail(code int, format string, args ...interface{}) (int, error) {
	return code, &RunError{Code: code, Err: fmt.Errorf("app: "+format, args...)}
}

func wrap(code int, err error, format string, args ...interface{}) (int, error) {
	if err == nil {
		return fail(code, format, args...)
	}
	message := fmt.Sprintf(format, args...)
	return code, &RunError{Code: code, Err: fmt.Errorf("app: %s: %w", message, err)}
}
