package trace

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/oyaguma3/eapaka_test/eap"
	"github.com/oyaguma3/eapaka_test/radiusc"

	eapaka "github.com/oyaguma3/go-eapaka"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

// Level controls the amount of trace detail.
type Level string

const (
	LevelNormal  Level = "normal"
	LevelVerbose Level = "verbose"
)

// Logger emits trace messages to the output.
type Logger struct {
	Level  Level
	Out    io.Writer
	Unsafe bool

	DumpEAPHex      bool
	DumpRadiusAttrs bool
}

// LogRadius writes a summary of the RADIUS message.
func (l *Logger) LogRadius(code radius.Code, packet *radius.Packet, eapPayload []byte, sess *eap.Session) {
	if l == nil || l.Out == nil {
		return
	}
	line := fmt.Sprintf("radius=%s", code.String())
	if packet != nil {
		state := rfc2865.State_Get(packet)
		if len(state) > 0 {
			line += " state=present"
		} else {
			line += " state=absent"
		}
		line += fmt.Sprintf(" attrs=%s", summarizeAttrs(packet))
	}
	if sess != nil {
		line += fmt.Sprintf(" outer=%s inner=%s", maskIdentity(sess.OuterIdentity), maskIdentity(sess.InnerIdentity))
	}
	fmt.Fprintln(l.Out, line)
	if l.Level == LevelVerbose {
		if l.DumpEAPHex {
			l.dumpEAP(eapPayload)
		}
		if l.DumpRadiusAttrs {
			l.dumpRadiusAttrs(packet)
		}
		l.dumpAKAAttributes(eapPayload)
		l.warnCalledStationID(packet)
	}
}

// LogChallengeResponse logs the EAP exchange step.
func (l *Logger) LogChallengeResponse(req *eap.Packet, resp *eap.Packet, sess *eap.Session) {
	if l == nil || l.Out == nil {
		return
	}
	reqType := eapTypeName(req)
	respType := eapTypeName(resp)
	line := fmt.Sprintf("eap request=%s response=%s", reqType, respType)
	if sess != nil {
		line += fmt.Sprintf(" outer=%s inner=%s", maskIdentity(sess.OuterIdentity), maskIdentity(sess.InnerIdentity))
	}
	fmt.Fprintln(l.Out, line)
}

// LogMPPE logs MPPE presence and optionally value prefixes.
func (l *Logger) LogMPPE(keys radiusc.MPPEKeys) {
	if l == nil || l.Out == nil {
		return
	}
	line := fmt.Sprintf("mppe send=%t recv=%t", keys.SendKeyPresent, keys.RecvKeyPresent)
	if l.Level == LevelVerbose {
		if keys.SendKeyPresent {
			line += fmt.Sprintf(" send_prefix=%s", maskBytes(keys.SendKey))
		}
		if keys.RecvKeyPresent {
			line += fmt.Sprintf(" recv_prefix=%s", maskBytes(keys.RecvKey))
		}
	}
	fmt.Fprintln(l.Out, line)
}

func summarizeAttrs(packet *radius.Packet) string {
	if packet == nil {
		return "none"
	}
	var parts []string
	if len(rfc2865.NASIPAddress_Get(packet)) > 0 {
		parts = append(parts, "nas_ip")
	}
	if rfc2865.NASIdentifier_GetString(packet) != "" {
		parts = append(parts, "nas_id")
	}
	if rfc2865.CalledStationID_GetString(packet) != "" {
		parts = append(parts, "called")
	}
	if rfc2865.CallingStationID_GetString(packet) != "" {
		parts = append(parts, "calling")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

func (l *Logger) warnCalledStationID(packet *radius.Packet) {
	if l == nil || l.Out == nil || packet == nil {
		return
	}
	called := rfc2865.CalledStationID_GetString(packet)
	if called == "" {
		return
	}
	if !calledStationIDOK(called) {
		fmt.Fprintln(l.Out, "warn called_station_id format unexpected")
	}
}

func calledStationIDOK(value string) bool {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return false
	}
	mac := parts[0]
	if len(mac) != 17 {
		return false
	}
	for i := 0; i < len(mac); i++ {
		switch i {
		case 2, 5, 8, 11, 14:
			if mac[i] != '-' {
				return false
			}
		default:
			c := mac[i]
			if !isHex(c) {
				return false
			}
		}
	}
	return true
}

func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func (l *Logger) dumpEAP(payload []byte) {
	if len(payload) == 0 {
		return
	}
	fmt.Fprintf(l.Out, "eap_hex=%s\n", hex.EncodeToString(payload))
}

func (l *Logger) dumpRadiusAttrs(packet *radius.Packet) {
	if packet == nil {
		return
	}
	var attrs []string
	for _, avp := range packet.Attributes {
		attrs = append(attrs, fmt.Sprintf("%d(len=%d)", avp.Type, len(avp.Attribute)))
	}
	if len(attrs) > 0 {
		fmt.Fprintf(l.Out, "radius_attrs=%s\n", strings.Join(attrs, ","))
	}
}

func (l *Logger) dumpAKAAttributes(payload []byte) {
	if len(payload) == 0 {
		return
	}
	pkt, err := eapaka.Parse(payload)
	if err != nil {
		return
	}
	if pkt.Type != eapaka.TypeAKA && pkt.Type != eapaka.TypeAKAPrime {
		return
	}
	var names []string
	for _, attr := range pkt.Attributes {
		names = append(names, fmt.Sprintf("%T", attr))
		if _, ok := attr.(*eapaka.AtPermanentIdReq); ok {
			fmt.Fprintln(l.Out, "aka_perm_id_req=true")
		}
		if kdfInput, ok := attr.(*eapaka.AtKdfInput); ok {
			fmt.Fprintf(l.Out, "aka_kdf_input=%s\n", kdfInput.NetworkName)
		}
		if randAttr, ok := attr.(*eapaka.AtRand); ok {
			fmt.Fprintf(l.Out, "aka_rand=%s\n", maskAKABytes(randAttr.Rand, l.Unsafe))
		}
		if autnAttr, ok := attr.(*eapaka.AtAutn); ok {
			fmt.Fprintf(l.Out, "aka_autn=%s\n", maskAKABytes(autnAttr.Autn, l.Unsafe))
		}
		if resAttr, ok := attr.(*eapaka.AtRes); ok {
			fmt.Fprintf(l.Out, "aka_res=%s\n", maskAKABytes(resAttr.Res, l.Unsafe))
		}
	}
	if len(names) > 0 {
		fmt.Fprintf(l.Out, "aka_attrs=%s\n", strings.Join(names, ","))
	}
}

func maskIdentity(identity string) string {
	if identity == "" {
		return ""
	}
	if len(identity) <= 4 {
		return "***"
	}
	return identity[:2] + "***" + identity[len(identity)-2:]
}

func maskBytes(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	if len(value) <= 4 {
		return "***"
	}
	return hex.EncodeToString(value[:2]) + "***"
}

func maskAKABytes(value []byte, unsafe bool) string {
	if unsafe {
		return hex.EncodeToString(value)
	}
	if len(value) == 0 {
		return ""
	}
	return fmt.Sprintf("%s(len=%d)", maskBytes(value), len(value))
}

func eapTypeName(pkt *eap.Packet) string {
	if pkt == nil {
		return "none"
	}
	switch pkt.Type {
	case eap.TypeIdentity:
		return "identity"
	case eap.TypeAKA:
		return "aka"
	case eap.TypeAKAPrime:
		return "aka'"
	default:
		return fmt.Sprintf("type=%d", pkt.Type)
	}
}

// ExtractEAPPayload extracts EAP-Message bytes from a RADIUS packet.
func ExtractEAPPayload(packet *radius.Packet) []byte {
	if packet == nil {
		return nil
	}
	payload, _ := rfc2869.EAPMessage_Lookup(packet)
	return payload
}
