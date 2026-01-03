package trace

import (
	"bytes"
	"testing"

	"github.com/oyaguma3/eapaka_test/eap"
	"github.com/oyaguma3/eapaka_test/radiusc"

	eapaka "github.com/oyaguma3/go-eapaka"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

func TestTraceNormal(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := &Logger{Level: LevelNormal, Out: buf}
	packet := radius.New(radius.CodeAccessRequest, []byte("secret"))
	_ = rfc2865.NASIdentifier_SetString(packet, "nas")
	payload := []byte{0x01, 0x02}
	_ = rfc2869.EAPMessage_Set(packet, payload)

	logger.LogRadius(radius.CodeAccessChallenge, packet, payload, &eap.Session{OuterIdentity: "user@example"})

	if buf.Len() == 0 {
		t.Fatalf("expected trace output")
	}
	if !bytes.Contains(buf.Bytes(), []byte("radius=Access-Challenge")) {
		t.Fatalf("expected radius code in output")
	}
}

func TestTraceVerboseAKA(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := &Logger{Level: LevelVerbose, Out: buf}

	req := &eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 1,
		Type:       eapaka.TypeAKA,
		Subtype:    eapaka.SubtypeIdentity,
		Attributes: []eapaka.Attribute{&eapaka.AtPermanentIdReq{}},
	}
	raw, err := req.Marshal()
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	logger.dumpAKAAttributes(raw)

	if !bytes.Contains(buf.Bytes(), []byte("aka_perm_id_req=true")) {
		t.Fatalf("expected perm id req trace")
	}
}

func TestTraceUnsafeAKAValues(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := &Logger{Level: LevelVerbose, Out: buf, Unsafe: true}

	req := &eapaka.Packet{
		Code:       eapaka.CodeRequest,
		Identifier: 1,
		Type:       eapaka.TypeAKA,
		Subtype:    eapaka.SubtypeChallenge,
		Attributes: []eapaka.Attribute{
			&eapaka.AtRand{Rand: bytes.Repeat([]byte{0x01}, 16)},
			&eapaka.AtAutn{Autn: bytes.Repeat([]byte{0x10}, 16)},
			&eapaka.AtRes{Res: []byte{0xaa, 0xbb}},
		},
	}
	raw, err := req.Marshal()
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	logger.dumpAKAAttributes(raw)

	if !bytes.Contains(buf.Bytes(), []byte("aka_rand=01010101010101010101010101010101")) {
		t.Fatalf("expected rand hex output")
	}
	if !bytes.Contains(buf.Bytes(), []byte("aka_autn=10101010101010101010101010101010")) {
		t.Fatalf("expected autn hex output")
	}
	if !bytes.Contains(buf.Bytes(), []byte("aka_res=aabb")) {
		t.Fatalf("expected res hex output")
	}
}

func TestTraceMPPE(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := &Logger{Level: LevelVerbose, Out: buf}
	logger.LogMPPE(radiusc.MPPEKeys{SendKeyPresent: true, SendKey: []byte{0x01, 0x02, 0x03}})

	if !bytes.Contains(buf.Bytes(), []byte("mppe send=true")) {
		t.Fatalf("expected mppe trace")
	}
}

func TestCalledStationIDWarning(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := &Logger{Level: LevelVerbose, Out: buf}
	packet := radius.New(radius.CodeAccessRequest, []byte("secret"))
	_ = rfc2865.CalledStationID_SetString(packet, "bad-format")

	logger.LogRadius(radius.CodeAccessRequest, packet, nil, nil)

	if !bytes.Contains(buf.Bytes(), []byte("warn called_station_id format unexpected")) {
		t.Fatalf("expected called_station_id warning")
	}
}
