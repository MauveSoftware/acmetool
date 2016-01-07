package acmeapi

import (
	"encoding/json"
	"fmt"
	denet "github.com/hlandau/degoutils/net"
	"time"
)

// Represents a Challenge which is part of an Authorization.
type Challenge struct {
	URI      string `json:"uri"`      // The URI of the challenge.
	Resource string `json:"resource"` // "challenge"

	Type      string    `json:"type"`
	Status    Status    `json:"status,omitempty"`
	Validated time.Time `json:"validated,omitempty"` // RFC 3339
	Token     string    `json:"token"`

	// tls-sni-01
	N int `json:"n,omitempty"`

	// proofOfPossession
	Certs []denet.Base64up `json:"certs,omitempty"`

	retryAt time.Time
}

// Represents an authorization. You can construct an authorization from only
// the URI; the authorization information will be fetched automatically.
type Authorization struct {
	URI      string `json:"-"`        // The URI of the authorization.
	Resource string `json:"resource"` // must be "new-authz" or "authz"

	Identifier   Identifier   `json:"identifier"`
	Status       Status       `json:"status,omitempty"`
	Expires      time.Time    `json:"expires,omitempty"` // RFC 3339 (ISO 8601)
	Challenges   []*Challenge `json:"challenges,omitempty"`
	Combinations [][]int      `json:"combinations,omitempty"`

	retryAt time.Time
}

// Represents a certificate which has been, or is about to be, issued.
type Certificate struct {
	URI      string `json:"-"`        // The URI of the certificate.
	Resource string `json:"resource"` // "new-cert"

	// The certificate data. DER.
	Certificate []byte `json:"-"`

	// Any required extra certificates, in DER form in the correct order.
	ExtraCertificates [][]byte `json:"-"`

	// DER. Consumers of this API will find that this is always nil; it is
	// used internally when submitting certificate requests.
	CSR denet.Base64up `json:"csr"`

	retryAt time.Time
}

// Represents an identifier for which an authorization is desired.
type Identifier struct {
	Type  string `json:"type"`  // must be "dns"
	Value string `json:"value"` // dns: a hostname.
}

// Represents the status of an authorization or challenge.
type Status string

const (
	StatusUnknown    Status = "unknown"
	StatusPending           = "pending"
	StatusProcessing        = "processing"
	StatusValid             = "valid"
	StatusInvalid           = "invalid"
	StatusRevoked           = "revoked"
)

// Returns true iff the status is a valid status.
func (s Status) Valid() bool {
	switch s {
	case "unknown", "pending", "processing", "valid", "invalid", "revoked":
		return true
	default:
		return false
	}
}

// Returns true iff the status is a final status.
func (s Status) Final() bool {
	switch s {
	case "valid", "invalid", "revoked":
		return true
	default:
		return false
	}
}

func (s *Status) UnmarshalJSON(data []byte) error {
	var ss string
	err := json.Unmarshal(data, &ss)
	if err != nil {
		return err
	}

	if !Status(ss).Valid() {
		return fmt.Errorf("not a valid status: %#v", ss)
	}

	*s = Status(ss)
	return nil
}

// © 2015 Hugo Landau <hlandau@devever.net>    MIT License