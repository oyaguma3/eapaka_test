package radiusc

import (
	"crypto/hmac"
	"crypto/md5"
	"fmt"

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
