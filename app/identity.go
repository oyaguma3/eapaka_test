package app

import (
	"cmp"
	"fmt"
	"slices"
	"time"

	"github.com/oyaguma3/eapaka_test/config"
	"github.com/oyaguma3/eapaka_test/eap"
	"github.com/oyaguma3/eapaka_test/idstore"
	"github.com/oyaguma3/eapaka_test/radiusc"
	"github.com/oyaguma3/eapaka_test/testcase"
	"github.com/oyaguma3/eapaka_test/trace"
)

func buildIDStore(cfg config.Config) (idstore.Store, error) {
	switch cfg.IdentityStore.Mode {
	case "", "memory":
		return idstore.NewMemoryStore(), nil
	case "file":
		if cfg.IdentityStore.Path == "" {
			return nil, fmt.Errorf("identity_store.path is required")
		}
		return &idstore.FileStore{Path: cfg.IdentityStore.Path}, nil
	default:
		return nil, fmt.Errorf("unsupported identity_store.mode %q", cfg.IdentityStore.Mode)
	}
}

// selectedReauth は、この実行で使う再認証コンテキストと、そのメソッド。
type selectedReauth struct {
	ctx     *idstore.Reauth
	eapType uint8
}

func (r *selectedReauth) contextFor(eapType uint8) *idstore.Reauth {
	if r == nil || r.eapType != eapType {
		return nil
	}
	return r.ctx
}

// selectIdentity は開始時の ID を選ぶ（設計書 §5.3 の identity_source）。再認証 ID を使うときは、
// そのコンテキストを返し、ストアからは外す（交換が完了しなくても再利用しない、RFC 4187 §4.1.1.8）。
func selectIdentity(tc testcase.Case, cfg config.Config, ids idstore.Store) (string, *selectedReauth, error) {
	eapType, prefix := eap.TypeAKA, "0"
	if tc.Method == "aka_prime" {
		eapType, prefix = eap.TypeAKAPrime, "6"
	}
	method := idstore.MethodFor(eapType)
	withRealm := func(user string) string {
		if cfg.Identity.Realm == "" {
			return user
		}
		return user + "@" + cfg.Identity.Realm
	}
	permanent := withRealm(prefix + cfg.SIM.IMSI)
	src := cmp.Or(tc.IdentitySource, "literal")
	if src == "literal" {
		return tc.Identity, nil, nil
	}
	if src == "permanent" {
		return permanent, nil, nil
	}
	e, err := ids.Get(cfg.SIM.IMSI, method)
	if err != nil {
		return "", nil, err
	}

	reuse := slices.ContainsFunc(tc.Faults, func(f testcase.Fault) bool { return f.At == "start" && f.Action == "reuse_reauth_id" })
	if src == "reauth" || (src == "auto" && e.Reauth != nil) {
		ctx := e.Reauth
		if reuse {
			// 異常系の注入: 直近に使った再認証 ID をもう一度使う（サーバは再認証してはならない）
			ctx = e.UsedReauth
		}
		if ctx == nil {
			return "", nil, fmt.Errorf("identity_source: reauth: no stored %s re-authentication identity", method)
		}
		// EAP-AKA' でネットワーク名が変わったら再認証しない（RFC 9048 §3.3）
		if eapType == eap.TypeAKAPrime && ctx.NetName != "" && cfg.EAP.AKAPrime.NetName != "" && ctx.NetName != cfg.EAP.AKAPrime.NetName {
			if src == "reauth" {
				return "", nil, fmt.Errorf("identity_source: reauth: the network name changed from %q", ctx.NetName)
			}
		} else {
			if !reuse {
				e.UsedReauth, e.Reauth = e.Reauth, nil
				if err := ids.Put(cfg.SIM.IMSI, method, e); err != nil {
					return "", nil, err
				}
			}
			return ctx.Identity, &selectedReauth{ctx: ctx, eapType: eapType}, nil
		}
	}
	if e.Pseudonym != nil {
		// 仮名にはレルムを含めない（RFC 4187 §10.10）ので、使うときにレルムを付ける
		return withRealm(e.Pseudonym.Username), nil, nil
	}
	if src == "pseudonym" {
		return "", nil, fmt.Errorf("identity_source: pseudonym: no stored %s pseudonym for the IMSI", method)
	}
	return permanent, nil, nil
}

// commitPending は、Access-Accept を受けたときに、受け取った仮名を識別子ストアに保存する
// （設計書 §4.1 のコミットの規則）。identity_store.persist が false なら保存しない。
func commitPending(sess *eap.Session, ids idstore.Store, imsi string, tc testcase.Case, logger *trace.Logger) {
	p := sess.Pending
	if (p.Pseudonym == "" && !p.AuthDone) || ids == nil || (tc.IdentityStore.Persist != nil && !*tc.IdentityStore.Persist) {
		return
	}
	method := idstore.MethodFor(p.Method)
	e, err := ids.Get(imsi, method)
	if err == nil {
		if p.Pseudonym != "" {
			e.Pseudonym = &idstore.Pseudonym{Username: p.Pseudonym, IssuedAt: time.Now().UTC()}
		}
		if p.AuthDone {
			// 受け取った再認証 ID で置き換える。受け取らなければ再認証の状態を破棄する（RFC 4187 §5.3）
			e.Reauth = p.Reauth
		}
		err = ids.Put(imsi, method, e)
	}
	if err != nil {
		logger.LogWarn(fmt.Sprintf("identity store: %v", err))
	}
}

// evaluate は、期待結果と観測結果に関する期待値を順に判定する。
func evaluate(tc testcase.Case, resp *radiusc.Response, accepted bool, obs eap.Observations) (int, error) {
	checks := []func() (int, error){func() (int, error) { return evaluateExpect(tc, resp, accepted) }}
	if accepted {
		checks = append(checks, func() (int, error) { return evaluateMSK(tc, obs) })
	}
	checks = append(checks,
		func() (int, error) { return evaluateBidding(tc, obs) },
		func() (int, error) { return evaluateNotification(tc, obs) },
		func() (int, error) { return evaluateIdentity(tc, obs) },
	)
	for _, check := range checks {
		if code, err := check(); code != 0 || err != nil {
			return code, err
		}
	}
	return 0, nil
}

// evaluateIdentity は、仮名・再認証 ID・AKA-Identity・AT_CHECKCODE の期待値を判定する。
func evaluateIdentity(tc testcase.Case, obs eap.Observations) (int, error) {
	e := tc.Expect
	presence := func(name, want string, got bool) error {
		if want != "" && (want == "present") != got {
			return fmt.Errorf("expect.%s=%s does not match", name, want)
		}
		return nil
	}
	for _, err := range []error{
		presence("next_pseudonym", e.NextPseudonym, obs.NextPseudonym),
		presence("next_reauth_id", e.NextReauthID, obs.NextReauthID),
	} {
		if err != nil {
			return fail(1, "%v", err)
		}
	}
	if e.IdentityRequests != nil && !slices.Equal(e.IdentityRequests, obs.IdentityRequests) {
		return fail(1, "expect.identity_requests=%v but received %v", e.IdentityRequests, obs.IdentityRequests)
	}
	if e.AuthType != "" && e.AuthType != obs.AuthType {
		return fail(1, "expect.auth_type=%s but the authentication was %q", e.AuthType, obs.AuthType)
	}
	if e.CounterTooSmallSent != nil && *e.CounterTooSmallSent != obs.CounterTooSmallSent {
		return fail(1, "expect.counter_too_small_sent=%t does not match", *e.CounterTooSmallSent)
	}
	switch e.Checkcode {
	case "verified":
		if obs.Checkcode != "verified" {
			return fail(1, "expect.checkcode=verified but AT_CHECKCODE was %q", cmp.Or(obs.Checkcode, "absent"))
		}
	case "absent":
		if obs.Checkcode != "" {
			return fail(1, "expect.checkcode=absent but AT_CHECKCODE was received")
		}
	}
	return 0, nil
}
