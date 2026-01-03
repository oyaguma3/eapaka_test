package radiusc

import (
	"context"
	"fmt"
	"net"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

// Attributes represents optional RADIUS attributes for Access-Request.
type Attributes struct {
	NASIPAddress     string
	NASIdentifier    string
	CalledStationID  string
	CallingStationID string
}

// Response wraps a RADIUS response with parsed fields.
type Response struct {
	Code   radius.Code
	EAP    []byte
	MPPE   MPPEKeys
	State  []byte
	Packet *radius.Packet
}

// Client is a RADIUS client with state retention for EAP sessions.
type Client struct {
	Addr    string
	Secret  string
	Timeout time.Duration
	Retries int

	State []byte

	client *radius.Client
}

// NewClient initializes a new RADIUS client.
func NewClient(addr, secret string, timeout time.Duration, retries int) *Client {
	return &Client{
		Addr:    addr,
		Secret:  secret,
		Timeout: timeout,
		Retries: retries,
	}
}

// ExchangeEAP sends an Access-Request with EAP-Message and returns the response.
func (c *Client) ExchangeEAP(ctx context.Context, userName string, eap []byte, attrs Attributes) (*Response, error) {
	if c == nil {
		return nil, fmt.Errorf("radiusc: client is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if c.Addr == "" {
		return nil, fmt.Errorf("radiusc: server address is required")
	}
	if c.Secret == "" {
		return nil, fmt.Errorf("radiusc: secret is required")
	}
	packet := radius.New(radius.CodeAccessRequest, []byte(c.Secret))
	if err := rfc2865.UserName_SetString(packet, userName); err != nil {
		return nil, err
	}
	if err := AddEAPMessage(packet, eap); err != nil {
		return nil, err
	}
	if len(c.State) > 0 {
		if err := rfc2865.State_Set(packet, c.State); err != nil {
			return nil, err
		}
	}
	if err := applyAttrs(packet, attrs); err != nil {
		return nil, err
	}
	if err := SetMessageAuthenticator(packet); err != nil {
		return nil, err
	}

	resp, err := c.exchange(ctx, packet)
	if err != nil {
		return nil, err
	}

	out := &Response{Code: resp.Code, Packet: resp}
	if state, err := rfc2865.State_Lookup(resp); err == nil {
		out.State = append([]byte(nil), state...)
		c.State = append([]byte(nil), state...)
	}
	if eapResp, ok, err := LookupEAPMessage(resp); err != nil {
		return nil, err
	} else if ok {
		out.EAP = eapResp
	}
	mppe, err := ExtractMPPEKeys(resp)
	if err != nil {
		return nil, err
	}
	out.MPPE = mppe
	return out, nil
}

// ResetState clears the retained RADIUS State attribute.
func (c *Client) ResetState() {
	if c == nil {
		return
	}
	c.State = nil
}

func (c *Client) exchange(ctx context.Context, packet *radius.Packet) (*radius.Packet, error) {
	client := c.client
	if client == nil {
		client = &radius.Client{}
	}
	if c.Timeout > 0 && c.Retries > 0 {
		client.Retry = c.Timeout
	} else {
		client.Retry = 0
	}
	if c.Timeout > 0 {
		total := c.Timeout
		if c.Retries > 0 {
			total = c.Timeout * time.Duration(c.Retries+1)
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, total)
		defer cancel()
	}
	return client.Exchange(ctx, packet, c.Addr)
}

func applyAttrs(packet *radius.Packet, attrs Attributes) error {
	if attrs.NASIPAddress != "" {
		ip := net.ParseIP(attrs.NASIPAddress)
		if ip == nil {
			return fmt.Errorf("radiusc: invalid nas_ip_address: %q", attrs.NASIPAddress)
		}
		if err := rfc2865.NASIPAddress_Set(packet, ip); err != nil {
			return err
		}
	}
	if attrs.NASIdentifier != "" {
		if err := rfc2865.NASIdentifier_SetString(packet, attrs.NASIdentifier); err != nil {
			return err
		}
	}
	if attrs.CalledStationID != "" {
		if err := rfc2865.CalledStationID_SetString(packet, attrs.CalledStationID); err != nil {
			return err
		}
	}
	if attrs.CallingStationID != "" {
		if err := rfc2865.CallingStationID_SetString(packet, attrs.CallingStationID); err != nil {
			return err
		}
	}
	return nil
}
