package config

import "github.com/oyaguma3/eapaka_test/testcase"

// ApplyTestcase overrides config values using a testcase's optional fields.
func ApplyTestcase(base Config, tc testcase.Case) Config {
	out := base

	if tc.Radius.TimeoutMS != nil {
		out.Radius.TimeoutMS = *tc.Radius.TimeoutMS
	}
	if tc.Radius.Retries != nil {
		out.Radius.Retries = *tc.Radius.Retries
	}
	if tc.Radius.Attrs.NASIPAddress != "" {
		out.RadiusAttrs.NASIPAddress = tc.Radius.Attrs.NASIPAddress
	}
	if tc.Radius.Attrs.NASIdentifier != "" {
		out.RadiusAttrs.NASIdentifier = tc.Radius.Attrs.NASIdentifier
	}
	if tc.Radius.Attrs.CalledStationID != "" {
		out.RadiusAttrs.CalledStationID = tc.Radius.Attrs.CalledStationID
	}
	if tc.Radius.Attrs.CallingStationID != "" {
		out.RadiusAttrs.CallingStationID = tc.Radius.Attrs.CallingStationID
	}

	if tc.EAP.MethodMismatchPolicy != "" {
		out.EAP.MethodMismatchPolicy = tc.EAP.MethodMismatchPolicy
	}
	if tc.EAP.OuterIdentityUpdateOnPermanentReq != nil {
		out.EAP.OuterIdentityUpdateOnPermanentReq = tc.EAP.OuterIdentityUpdateOnPermanentReq
	}
	if tc.EAP.PermanentIDPolicy != "" {
		out.EAP.PermanentIDPolicy = tc.EAP.PermanentIDPolicy
	}
	if tc.EAP.AKAPrime.NetName != "" {
		out.EAP.AKAPrime.NetName = tc.EAP.AKAPrime.NetName
	}

	return out
}
