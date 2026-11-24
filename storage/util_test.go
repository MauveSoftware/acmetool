package storage

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
)

// Make sure the determineKeyIDFromKey and determineKeyIDFromPublicKey
// functions produce the same result, and that it matches the key ID derived
// from a certificate for that key (key IDs are persisted, so they must stay
// stable).
func TestKeyID(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}

	tests := []struct {
		name string
		key  crypto.Signer
	}{
		{"rsa", rsaKey},
		{"ecdsa", ecKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyID, err := determineKeyIDFromKey(tt.key)
			if err != nil {
				t.Fatalf("determineKeyIDFromKey: %v", err)
			}

			keyID2, err := DetermineKeyIDFromPublicKey(tt.key.Public())
			if err != nil {
				t.Fatalf("DetermineKeyIDFromPublicKey: %v", err)
			}

			if keyID != keyID2 {
				t.Fatalf("key ID mismatch between private and public key: %#v != %#v", keyID, keyID2)
			}

			tpl := &x509.Certificate{SerialNumber: big.NewInt(1)}
			der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, tt.key.Public(), tt.key)
			if err != nil {
				t.Fatalf("creating certificate: %v", err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatalf("parsing certificate: %v", err)
			}

			if certKeyID := determineKeyIDFromCert(cert); keyID != certKeyID {
				t.Fatalf("key ID mismatch between key and certificate: %#v != %#v", keyID, certKeyID)
			}
		})
	}
}
