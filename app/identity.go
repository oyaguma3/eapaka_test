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

// selectIdentity は開始時の ID を選ぶ（設計書 §5.3 の identity_source）。
func selectIdentity(tc testcase.Case, cfg config.Config, ids idstore.Store) (string, error) {
	eapType, prefix := eap.TypeAKA, "0"
	if tc.Method == "aka_prime" {
		eapType, prefix = eap.TypeAKAPrime, "6"
	}
	withRealm := func(user string) string {
		if cfg.Identity.Realm == "" {
			return user
		}
		return user + "@" + cfg.Identity.Realm
	}
	pseudonym := func() (string, error) {
		e, err := ids.Get(cfg.SIM.IMSI, idstore.MethodFor(eapType))
		if err != nil {
			return "", err
		}
		if e.Pseudonym == nil {
			return "", nil
		}
		// 仮名にはレルムを含めない（RFC 4187 §10.10）ので、使うときにレルムを付ける
		return withRealm(e.Pseudonym.Username), nil
	}
	switch cmp.Or(tc.IdentitySource, "literal") {
	case "literal":
		return tc.Identity, nil
	case "permanent":
		return withRealm(prefix + cfg.SIM.IMSI), nil
	case "pseudonym":
		id, err := pseudonym()
		if err == nil && id == "" {
			err = fmt.Errorf("identity_source: pseudonym: no stored %s pseudonym for the IMSI", tc.Method)
		}
		return id, err
	case "auto":
		id, err := pseudonym()
		if err != nil || id != "" {
			return id, err
		}
		return withRealm(prefix + cfg.SIM.IMSI), nil
	default:
		return "", fmt.Errorf("unsupported identity_source %q", tc.IdentitySource)
	}
}

// commitPending は、Access-Accept を受けたときに、受け取った仮名を識別子ストアに保存する
// （設計書 §4.1 のコミットの規則）。identity_store.persist が false なら保存しない。
func commitPending(sess *eap.Session, ids idstore.Store, imsi string, tc testcase.Case, logger *trace.Logger) {
	p := sess.Pending
	if p.Pseudonym == "" || ids == nil || (tc.IdentityStore.Persist != nil && !*tc.IdentityStore.Persist) {
		return
	}
	method := idstore.MethodFor(p.Method)
	e, err := ids.Get(imsi, method)
	if err == nil {
		e.Pseudonym = &idstore.Pseudonym{Username: p.Pseudonym, IssuedAt: time.Now().UTC()}
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
