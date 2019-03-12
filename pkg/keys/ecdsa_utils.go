package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// Read a public key from a hex string (A P-256 FIPS 186.3 with ANSI X9.62 encoding (ecdsa public key of  a 256 bits curve)).
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

func PemEncodePublicKey(pubKey *ecdsa.PublicKey) (string, error) {
	if encoded, err := x509.MarshalPKIXPublicKey(pubKey); err != nil {
		return "", err
	} else {
		return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})), nil
	}
}

func PemDecodePublicKey(pubKey string) (*ecdsa.PublicKey, error) {
	decoded, _ := pem.Decode([]byte(pubKey))
	keyBytes := decoded.Bytes
	if genericPublicKey, err := x509.ParsePKIXPublicKey(keyBytes); err != nil {
		return nil, err
	} else {
		return genericPublicKey.(*ecdsa.PublicKey), nil
	}
}
