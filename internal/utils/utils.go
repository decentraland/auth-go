package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Extracts headers values. If the key is not present retrieves an error
func ExtractRequiredField(m map[string]string, key string) (string, error) {
	r := m[key]
	if len(r) == 0 {
		return "", fmt.Errorf("missing required credential: %s", key)
	}
	return r, nil
}

// Adds the Ox prefix to the string if not present
func FormatHexString(toPad string) string {
	if strings.HasPrefix(toPad, "0x") {
		return toPad
	}
	return "0x" + toPad
}

// Removes the Ox prefix from the string if present
func RemoveHexPrefix(value string) string {
	if !strings.HasPrefix(value, "0x") {
		return value
	}
	return value[2:]
}

// Reads the request content into a byte array
func ReadRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	b, err := r.GetBody()
	if err != nil {
		return nil, err
	}
	content, err := ioutil.ReadAll(b)
	if err != nil {
		return nil, err
	}
	return content, nil
}

// Retrieves the Address that generated the certificate  and the public ephemeral key from the identity header
func ParseTokensWithRegex(idHeader string, pattern string) ([]string, error) {
	idRegex := *regexp.MustCompile(pattern)
	if !idRegex.MatchString(idHeader) {
		return nil, fmt.Errorf("malformed 'x-identity' header: %s", idHeader)
	}
	matches := idRegex.FindAllStringSubmatch(idHeader, -1)
	return matches[0][1:], nil
}

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

// Retrieves a sha256 from the following message: request method + request url + timestamp + request body
func GenerateHttpRequestHash(r *http.Request, timestamp int64) ([]byte, error) {
	method := r.Method
	url := r.URL.String()

	b, err := ReadRequestBody(r)
	if err != nil {
		return nil, err
	}

	toSign := []byte(method)
	toSign = append(toSign, []byte(url)...)
	toSign = append(toSign, []byte(strconv.FormatInt(timestamp, 10))...)
	if b != nil {
		toSign = append(toSign, b...)
	}
	result := sha256.Sum256(toSign)
	return result[:], nil
}

// Retrieves a sha256 from the following message: timestamp + message
func GenerateMessageHash(message []byte, timestamp int64) ([]byte, error) {
	toSign := []byte(strconv.FormatInt(timestamp, 10))
	toSign = append(toSign, message...)

	result := sha256.Sum256(toSign)
	return result[:], nil
}

func SignMessage(msg []byte, privKey *ecdsa.PrivateKey) ([]byte, error) {
	signature, err := secp256k1.Sign(msg, crypto.FromECDSA(privKey))
	if err != nil {
		return nil, err
	}
	return signature[:len(signature)-1], nil
}
