package config

import (
	"testing"

	"github.com/oyaguma3/eapaka_test/testcase"
)

func TestApplyTestcaseOverrides(t *testing.T) {
	base := Config{
		Radius: RadiusConfig{
			ServerAddr: "127.0.0.1:1812",
			Secret:     "secret",
			TimeoutMS:  1000,
			Retries:    3,
		},
		RadiusAttrs: RadiusAttrs{
			NASIPAddress: "192.0.2.10",
		},
		EAP: EAPConfig{
			MethodMismatchPolicy: DefaultMethodMismatchPolicy,
			PermanentIDPolicy:    DefaultPermanentIDPolicy,
		},
	}
	outerUpdate := true
	base.EAP.OuterIdentityUpdateOnPermanentReq = &outerUpdate

	newTimeout := 500
	newRetries := 1
	updateOuter := false
	caseData := testcase.Case{
		Radius: testcase.Radius{
			TimeoutMS: &newTimeout,
			Retries:   &newRetries,
			Attrs: testcase.RadiusAttrs{
				CalledStationID: "aa-bb-cc-dd-ee-ff:MySSID",
			},
		},
		EAP: testcase.EAP{
			MethodMismatchPolicy:              "strict",
			OuterIdentityUpdateOnPermanentReq: &updateOuter,
			PermanentIDPolicy:                 "deny",
			AKAPrime: testcase.AKAPrime{
				NetName: "wlan.example",
			},
		},
	}

	merged := ApplyTestcase(base, caseData)
	if merged.Radius.TimeoutMS != 500 || merged.Radius.Retries != 1 {
		t.Fatalf("expected radius overrides applied")
	}
	if merged.RadiusAttrs.CalledStationID != "aa-bb-cc-dd-ee-ff:MySSID" {
		t.Fatalf("expected radius attrs override applied")
	}
	if merged.EAP.MethodMismatchPolicy != "strict" || merged.EAP.PermanentIDPolicy != "deny" {
		t.Fatalf("expected eap overrides applied")
	}
	if merged.EAP.OuterIdentityUpdateOnPermanentReq == nil || *merged.EAP.OuterIdentityUpdateOnPermanentReq != false {
		t.Fatalf("expected outer identity update override applied")
	}
	if merged.EAP.AKAPrime.NetName != "wlan.example" {
		t.Fatalf("expected aka prime net name override applied")
	}
}
