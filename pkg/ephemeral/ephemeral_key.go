package ephemeral

import (
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/decentraland/auth-go/internal/ethereum/crypto"
	"github.com/decentraland/auth-go/internal/ethereum/hexutil"

	"github.com/decentraland/auth-go/pkg/commons"

	"encoding/hex"
)

// EphemeralKey Short live key
type EphemeralKey struct { //nolint
	PrivateKey *ecdsa.PrivateKey
}

// EphemeralKeyConfig Configuration
type EphemeralKeyConfig struct { //nolint
	PrivateKey *ecdsa.PrivateKey
}

// NewEphemeralKey generates a EphemeralKey which is basically a ecdsa key
func NewEphemeralKey(config *EphemeralKeyConfig) (*EphemeralKey, error) {
	eph := &EphemeralKey{PrivateKey: config.PrivateKey}

	if eph.PrivateKey == nil {
		pvKey, err := crypto.GenerateKey()
		eph.PrivateKey = pvKey
		if err != nil {
			return nil, err
		}
	}

	return eph, nil
}

// PublicKey retrieves the public key of the private key generated
func (c *EphemeralKey) PublicKey() *ecdsa.PublicKey {
	return &c.PrivateKey.PublicKey
}

// AddRequestHeaders adds all  needed credentials to authenticate the credential owner as request headers
func (c *EphemeralKey) AddRequestHeaders(r *http.Request, accessToken string) error {
	timestamp := time.Now().Unix()

	msg, err := commons.GenerateHTTPRequestHash(r, timestamp)
	if err != nil {
		return err
	}

	fieldExtractor := func() (strings map[string]string, e error) {
		return c.generateCredentials(msg, accessToken, timestamp)
	}

	return completeRequest(r, fieldExtractor)
}

// MakeCredentials generates all the needed credentials to authenticate the credential owner
func (c *EphemeralKey) MakeCredentials(message []byte, accessToken string) (map[string]string, error) {
	timestamp := time.Now().Unix()

	msgHash, err := commons.GenerateMessageHash(message, timestamp)
	if err != nil {
		return nil, err
	}
	return c.generateCredentials(msgHash, accessToken, timestamp)
}

func (c *EphemeralKey) generateCredentials(
	message []byte, accessToken string, timestamp int64) (map[string]string, error) {

	signature, err := commons.SignMessage(message, c.PrivateKey)
	if err != nil {
		return nil, err
	}

	fields := map[string]string{}
	pubKey := hexutil.Encode(crypto.CompressPubkey(&c.PrivateKey.PublicKey))

	fields["x-signature"] = hex.EncodeToString(signature)
	fields["x-identity"] = fmt.Sprintf("public key derived address: %s", pubKey)
	fields["x-timestamp"] = strconv.FormatInt(timestamp, 10)
	fields["x-access-token"] = accessToken

	return fields, nil
}

func completeRequest(r *http.Request, readFields func() (map[string]string, error)) error {
	fields, err := readFields()
	if err != nil {
		return err
	}

	for header, value := range fields {
		r.Header.Set(header, value)
	}

	return nil
}
