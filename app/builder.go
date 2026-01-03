package app

import (
	"encoding/hex"
	"fmt"

	"github.com/oyaguma3/eapaka_test/config"
	"github.com/oyaguma3/eapaka_test/eap"
	"github.com/oyaguma3/eapaka_test/eapmethod/aka"
	"github.com/oyaguma3/eapaka_test/sqnstore"
	"github.com/oyaguma3/eapaka_test/testcase"
)

// BuildPeer constructs the EAP peer and AKA/AKA' methods from config/testcase.
func BuildPeer(cfg config.Config, tc testcase.Case, store sqnstore.Store) (*eap.Peer, error) {
	merged := config.ApplyTestcase(cfg, tc)
	ki, err := decodeHex("ki", merged.SIM.KI, 16)
	if err != nil {
		return nil, err
	}
	opc, err := decodeHex("opc", merged.SIM.OPC, 16)
	if err != nil {
		return nil, err
	}
	amf, err := decodeHex("amf", merged.SIM.AMF, 2)
	if err != nil {
		return nil, err
	}
	sqnInitial, err := sqnstore.ParseSQNHex(merged.SIM.SQNInitialHex)
	if err != nil {
		return nil, err
	}
	permanentPolicy := merged.EAP.PermanentIDPolicy
	outerUpdate := merged.EAP.OuterIdentityUpdateOnPermanentReq
	permanentOverride := tc.EAP.PermanentIdentityOverride

	akaMethod, err := aka.New(aka.Options{
		MethodType:                        eap.TypeAKA,
		IMSI:                              merged.SIM.IMSI,
		KI:                                ki,
		OPC:                               opc,
		AMF:                               amf,
		Realm:                             merged.Identity.Realm,
		InitialSQN:                        sqnInitial,
		SQNStore:                          store,
		PermanentIDPolicy:                 permanentPolicy,
		PermanentIdentityOverride:         permanentOverride,
		OuterIdentityUpdateOnPermanentReq: outerUpdate,
	})
	if err != nil {
		return nil, err
	}
	akaPrimeMethod, err := aka.New(aka.Options{
		MethodType:                        eap.TypeAKAPrime,
		IMSI:                              merged.SIM.IMSI,
		KI:                                ki,
		OPC:                               opc,
		AMF:                               amf,
		NetName:                           merged.EAP.AKAPrime.NetName,
		Realm:                             merged.Identity.Realm,
		InitialSQN:                        sqnInitial,
		SQNStore:                          store,
		PermanentIDPolicy:                 permanentPolicy,
		PermanentIdentityOverride:         permanentOverride,
		OuterIdentityUpdateOnPermanentReq: outerUpdate,
	})
	if err != nil {
		return nil, err
	}

	session := &eap.Session{OuterIdentity: tc.Identity}
	peer := eap.NewPeer(session, akaMethod, akaPrimeMethod)
	if merged.EAP.MethodMismatchPolicy != "" {
		peer.MethodPolicy = eap.MethodMismatchPolicy(merged.EAP.MethodMismatchPolicy)
	}
	return peer, nil
}

func decodeHex(label, value string, expected int) ([]byte, error) {
	b, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("app: invalid %s hex: %w", label, err)
	}
	if len(b) != expected {
		return nil, fmt.Errorf("app: %s must be %d bytes", label, expected)
	}
	return b, nil
}
