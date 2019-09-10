package commons

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"github.com/decentraland/auth-go/internal/ethereum/crypto"
	"github.com/decentraland/auth-go/internal/ethereum/secp256k1"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
)

// ReadRequestBody reads the request content into a byte array
func ReadRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	b := r.Body

	content, err := ioutil.ReadAll(b)
	if err != nil {
		return nil, err
	}
	r.Body = ioutil.NopCloser(bytes.NewReader(content))
	return content, nil
}

// GenerateHTTPRequestHash retrieves a sha256 from the following message:
// request method + request url + timestamp + request body
func GenerateHTTPRequestHash(r *http.Request, timestamp int64) ([]byte, error) {
	method := r.Method

	u, err := url.QueryUnescape(r.URL.String())
	if err != nil {
		return nil, err
	}

	b, err := ReadRequestBody(r)
	if err != nil {
		return nil, err
	}

	toSign := []byte(method)
	toSign = append(toSign, []byte(u)...)
	toSign = append(toSign, []byte(strconv.FormatInt(timestamp, 10))...)
	if b != nil {
		toSign = append(toSign, b...)
	}
	result := sha256.Sum256(toSign)
	return result[:], nil
}

// GenerateMessageHash retrieves a sha256 from the following message: timestamp + message
func GenerateMessageHash(message []byte, timestamp int64) ([]byte, error) {
	toSign := []byte(strconv.FormatInt(timestamp, 10))
	toSign = append(toSign, message...)

	result := sha256.Sum256(toSign)
	return result[:], nil
}

// SignMessage sign msg using privKey
func SignMessage(msg []byte, privKey *ecdsa.PrivateKey) ([]byte, error) {
	signature, err := secp256k1.Sign(msg, crypto.FromECDSA(privKey))
	if err != nil {
		return nil, err
	}
	return signature[:len(signature)-1], nil
}
