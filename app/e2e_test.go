package app

import (
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/oyaguma3/eapaka_test/config"
	"github.com/oyaguma3/eapaka_test/internal/fakeserver"
	"github.com/oyaguma3/eapaka_test/testcase"

	eapaka "github.com/oyaguma3/go-eapaka"
)

const (
	e2eSecret  = "testing123"
	e2eKI      = "00112233445566778899aabbccddeeff"
	e2eOPC     = "ffeeddccbbaa99887766554433221100"
	e2eRealm   = "wlan.mnc010.mcc440.3gppnetwork.org"
	e2eNetName = "WLAN"
)

// startServer は疑似サーバを起動する。cfg の Secret・KI・OPC・NetName が空ならテスト用の値を入れる。
func startServer(t *testing.T, cfg fakeserver.Config) *fakeserver.Server {
	t.Helper()
	if cfg.Secret == "" {
		cfg.Secret = e2eSecret
	}
	if cfg.KI == nil {
		cfg.KI = mustHex(t, e2eKI)
	}
	if cfg.OPC == nil {
		cfg.OPC = mustHex(t, e2eOPC)
	}
	if cfg.NetName == "" {
		cfg.NetName = e2eNetName
	}
	return fakeserver.StartT(t, cfg)
}

// e2eConfig は疑似サーバに向けた設定を返す。SQN ストアはメモリに置く。
func e2eConfig(srv *fakeserver.Server) config.Config {
	cfg := config.Config{
		Radius:   config.RadiusConfig{ServerAddr: srv.Addr(), Secret: e2eSecret, TimeoutMS: 500, Retries: 1},
		EAP:      config.EAPConfig{AKAPrime: config.AKAPrimeConfig{NetName: e2eNetName}},
		Identity: config.IdentityConfig{Realm: e2eRealm},
		SIM: config.SIMConfig{
			IMSI: "440100123456789", KI: e2eKI, OPC: e2eOPC, AMF: "8000", SQNInitialHex: "000000000000",
		},
		SQNStore: config.SQNStoreConfig{Mode: "memory"},
	}
	cfg.ApplyDefaults()
	return cfg
}

// e2eCase はテストケースを返す。トレースは一時ファイルに書く。
func e2eCase(t *testing.T, identity, result string) testcase.Case {
	t.Helper()
	return testcase.Case{
		Version:  1,
		Name:     t.Name(),
		Identity: identity,
		Expect:   testcase.Expect{Result: result},
		Trace:    testcase.Trace{Level: "verbose", SavePath: filepath.Join(t.TempDir(), "trace.log")},
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestE2EFullAuthentication(t *testing.T) {
	tests := []struct {
		name     string
		method   uint8
		identity string
	}{
		{"aka", eapaka.TypeAKA, "0440100123456789@" + e2eRealm},
		{"aka_prime", eapaka.TypeAKAPrime, "6440100123456789@" + e2eRealm},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startServer(t, fakeserver.Config{Method: tt.method})
			tc := e2eCase(t, tt.identity, "accept")
			code, err := RunCase(t.Context(), e2eConfig(srv), tc)
			if err != nil || code != 0 {
				t.Fatalf("RunCase = %d, %v; want 0", code, err)
			}
		})
	}
}
