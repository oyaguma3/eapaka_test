package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/oyaguma3/eapaka_test/config"
	"github.com/oyaguma3/eapaka_test/conformance"
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

// Result は 1 ケースの実行結果。
type Result struct {
	ExitCode   int
	Err        error
	Violations []conformance.Violation
	Obs        eap.Observations
}

// RunCase executes a single testcase and returns the exit code (0/1/2).
func RunCase(ctx context.Context, cfg config.Config, tc testcase.Case) (int, error) {
	res := Run(ctx, cfg, tc)
	return res.ExitCode, res.Err
}

// Run executes a single testcase and returns the result including conformance violations.
// 期待結果と一致していても、fail の違反があれば exit 1 にする（設計書 §6.1）。
func Run(ctx context.Context, cfg config.Config, tc testcase.Case) Result {
	merged := config.ApplyTestcase(cfg, tc)
	policy, err := merged.Conformance.Policy()
	if err != nil {
		code, err := wrap(2, err, "conformance policy")
		return Result{ExitCode: code, Err: err}
	}
	rec := conformance.NewRecorder(policy)
	logger := buildLogger(tc)
	rec.OnReport = logger.LogViolation

	var res Result
	peer, err := setupPeer(cfg, tc)
	if err != nil {
		res.ExitCode, res.Err = wrap(2, err, "setup")
	} else {
		peer.Session.Conformance = rec
		peer.Session.OnWarn = logger.LogWarn
		res.ExitCode, res.Err = exchange(ctx, merged, tc, peer, rec, logger)
		res.Obs = peer.Session.Obs
	}
	res.Violations = rec.Violations()
	if res.ExitCode == 0 && rec.Failed() {
		res.ExitCode, res.Err = fail(1, "conformance violations: %s", strings.Join(rec.FailedIDs(), ","))
	}
	logger.LogConformanceSummary(res.Violations)
	return res
}

// setupPeer は SQN ストアと EAP ピアを用意する。
func setupPeer(cfg config.Config, tc testcase.Case) (*eap.Peer, error) {
	merged := config.ApplyTestcase(cfg, tc)
	store, err := buildStore(merged, tc)
	if err != nil {
		return nil, fmt.Errorf("build store: %w", err)
	}
	if tc.SQN.Reset {
		if err := store.Reset(merged.SIM.IMSI); err != nil {
			return nil, fmt.Errorf("sqn reset: %w", err)
		}
	}
	peer, err := BuildPeer(cfg, tc, store)
	if err != nil {
		return nil, fmt.Errorf("build peer: %w", err)
	}
	if peer.Session == nil || peer.Session.OuterIdentity == "" {
		return nil, errors.New("outer identity is required")
	}
	return peer, nil
}

// exchange は RADIUS で EAP をやりとりし、最後の応答を期待結果と比べる。
func exchange(ctx context.Context, merged config.Config, tc testcase.Case, peer *eap.Peer, rec *conformance.Recorder, logger *trace.Logger) (int, error) {
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

	userName := peer.Session.OuterIdentity
	respPkt := &eap.Packet{
		Code:       eap.CodeResponse,
		Identifier: 0,
		Type:       eap.TypeIdentity,
		TypeData:   []byte(userName),
	}

	for round := 1; ; round++ {
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
		rec.SetRound(round)
		checkResponse(rec, resp, respPkt.Identifier, peer.Session.Obs)

		switch resp.Code {
		case radius.CodeAccessChallenge:
			if len(resp.EAP) == 0 {
				// R-03b として記録済み。サーバの誤りで続けられないので FAIL にする
				return fail(1, "missing EAP-Message in Access-Challenge")
			}
			reqPkt, err := eap.Parse(resp.EAP)
			if err != nil {
				return wrap(2, err, "parse EAP request")
			}
			nextResp, err := peer.Handle(reqPkt)
			if err != nil {
				if _, ok := errors.AsType[*eap.MethodMismatchError](err); ok {
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
			if peer.Session.OuterIdentity != "" {
				userName = peer.Session.OuterIdentity
			}
		case radius.CodeAccessAccept:
			verifyMSK(peer.Session, resp, merged.Radius.Secret, merged.MPPE.Mapping)
			if logger != nil {
				logger.LogMPPE(resp.MPPE)
				logger.LogMSK(peer.Session.Obs)
			}
			if code, err := evaluateExpect(tc, resp, true); code != 0 || err != nil {
				return code, err
			}
			if code, err := evaluateMSK(tc, peer.Session.Obs); code != 0 || err != nil {
				return code, err
			}
			if code, err := evaluateBidding(tc, peer.Session.Obs); code != 0 || err != nil {
				return code, err
			}
			return evaluateNotification(tc, peer.Session.Obs)
		case radius.CodeAccessReject:
			if logger != nil {
				logger.LogMPPE(resp.MPPE)
			}
			if code, err := evaluateExpect(tc, resp, false); code != 0 || err != nil {
				return code, err
			}
			if code, err := evaluateBidding(tc, peer.Session.Obs); code != 0 || err != nil {
				return code, err
			}
			return evaluateNotification(tc, peer.Session.Obs)
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
		checkPresence := false
		if tc.Expect.RejectHintCheckPresence != nil {
			checkPresence = *tc.Expect.RejectHintCheckPresence
		}
		hint := rfc2865.ReplyMessage_GetString(resp.Packet)
		if hint == "" {
			if checkPresence {
				return fail(1, "reject_hint_contains missing Reply-Message")
			}
		} else if !strings.Contains(hint, tc.Expect.RejectHintContains) {
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

func fail(code int, format string, args ...any) (int, error) {
	return code, &RunError{Code: code, Err: fmt.Errorf("app: "+format, args...)}
}

func wrap(code int, err error, format string, args ...any) (int, error) {
	if err == nil {
		return fail(code, format, args...)
	}
	message := fmt.Sprintf(format, args...)
	return code, &RunError{Code: code, Err: fmt.Errorf("app: %s: %w", message, err)}
}
