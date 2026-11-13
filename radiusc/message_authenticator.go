package radiusc

import (
	"crypto/hmac"
	"crypto/md5"
	"fmt"
	"slices"

	"layeh.com/radius"
	"layeh.com/radius/rfc2869"
)

// SetMessageAuthenticator computes and sets Message-Authenticator for the packet.
func SetMessageAuthenticator(p *radius.Packet) error {
	if p == nil {
		return fmt.Errorf("radiusc: packet is nil")
	}
	if len(p.Secret) == 0 {
		return fmt.Errorf("radiusc: secret is required for message-authenticator")
	}
	zero := make([]byte, 16)
	if err := rfc2869.MessageAuthenticator_Set(p, zero); err != nil {
		return err
	}
	raw, err := p.MarshalBinary()
	if err != nil {
		return err
	}
	mac := hmac.New(md5.New, p.Secret)
	if _, err := mac.Write(raw); err != nil {
		return err
	}
	sum := mac.Sum(nil)
	return rfc2869.MessageAuthenticator_Set(p, sum)
}

// VerifyResponseMessageAuthenticator は、Access-Accept/Reject/Challenge の
// Message-Authenticator を検証する（RFC 3579 §3.2）。Authenticator 欄を対応する
// Access-Request の Request Authenticator に置き換え、Message-Authenticator を 0 にして
// HMAC-MD5 を計算する。属性がなければ present が false。複数あれば valid は false。
func VerifyResponseMessageAuthenticator(resp *radius.Packet, reqAuth [16]byte, secret []byte) (present, valid bool, err error) {
	if resp == nil {
		return false, false, fmt.Errorf("radiusc: packet is nil")
	}
	idx := -1
	for i, avp := range resp.Attributes {
		if avp.Type != rfc2869.MessageAuthenticator_Type {
			continue
		}
		if idx >= 0 {
			return true, false, nil
		}
		idx = i
	}
	if idx < 0 {
		return false, false, nil
	}
	received := resp.Attributes[idx].Attribute
	if len(received) != md5.Size {
		return true, false, nil
	}
	q := *resp
	q.Authenticator = reqAuth
	q.Attributes = slices.Clone(resp.Attributes)
	q.Attributes[idx] = &radius.AVP{Type: rfc2869.MessageAuthenticator_Type, Attribute: make(radius.Attribute, md5.Size)}
	raw, err := q.MarshalBinary()
	if err != nil {
		return true, false, err
	}
	mac := hmac.New(md5.New, secret)
	mac.Write(raw)
	return true, hmac.Equal(mac.Sum(nil), received), nil
}
