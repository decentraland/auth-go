package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// ReadPublicKey reads a public key from a hex string (A P-256 FIPS 186.3 with
// ANSI X9.62 encoding (ecdsa public key of  a 256 bits curve)).
func ReadPublicKey(hexKey string) (*ecdsa.PublicKey, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %s", err.Error())
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), key)
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

// PemEncodePublicKey encodes ecdsa.PublicKey into Pem format
func PemEncodePublicKey(pubKey *ecdsa.PublicKey) (string, error) {
	encoded, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})), nil
}

// PemDecodePublicKey decodes a Pem formatted string into a ecdsa.PublicKey
func PemDecodePublicKey(pubKey string) (*ecdsa.PublicKey, error) {
	decoded, _ := pem.Decode([]byte(pubKey))
	keyBytes := decoded.Bytes
	genericPublicKey, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, err
	}
	return genericPublicKey.(*ecdsa.PublicKey), nil
}
