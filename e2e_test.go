package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/decentraland/authentication-go/auth"
	"github.com/decentraland/authentication-go/authentication"
	"github.com/decentraland/authentication-go/authorization"
	"github.com/decentraland/authentication-go/config"
	"github.com/decentraland/authentication-go/utils"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/decentraland/authentication-go/ephemeralkey"
	http2 "github.com/decentraland/authentication-go/http"
	"github.com/stretchr/testify/assert"
)

var runIntegrationTests = os.Getenv("RUN_IT") == "true"

func TestEphemeralKeys(t *testing.T) {
	if !runIntegrationTests {
		t.Skip("Skipping integration test. To run it set RUN_IT=true")
	}

	eth := os.Getenv("ETH_NODE")
	pass := os.Getenv("PASSPHRASE")

	g, _ := ephemeralkey.NewEphemeralKeysGenerator(eth, 10)

	acc, err := g.GetDefaultAccount()

	if err != nil {
		t.Error(err.Error())
	}
	credential, err := g.GenerateEphemeralKeys("0x12345", acc, pass)

	assert.Nil(t, err)
	assert.NotNil(t, credential)

	req, err := buildPostRequest(credential)
	if err != nil {
		t.Error(err.Error())
	}

	checkRequest(t, req, credential)

	get, err := buildGetRequest(credential)
	if err != nil {
		t.Error(err.Error())
	}

	checkRequest(t, get, credential)
}

func checkRequest(t *testing.T, req *http.Request, c *ephemeralkey.Credentials) {
	dclApi := os.Getenv("DCL_API")

	config := &config.AuthConfig{DclApi: dclApi, RequestAllowedTTL: 100000}

	authHandler := auth.NewAuthProvider(authentication.NewStrategy(config), authorization.NewStrategy(config))

	r, err := http2.TransformHttpRequest(req)
	if err != nil {
		t.Fail()
	}

	validation, err := authHandler.ApproveRequest(r)
	if err != nil {
		t.Error(err.Error())
	}

	assert.True(t, validation)
}

func addHeaders(c *ephemeralkey.Credentials, r *http.Request) error {
	timestamp := strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10)
	msg, err := buildMessageToVerify(r, timestamp)
	if err != nil {
		return err
	}

	signature, err := secp256k1.Sign(msg, crypto.FromECDSA(c.EphemeralPrivateKey))
	if err != nil {
		return err
	}

	sig := signature[:len(signature)-1]

	r.Header.Set("x-signature", hex.EncodeToString(sig))
	r.Header.Set("x-identity", fmt.Sprintf("decentraland:%s/temp/%s", c.Address, hexutil.Encode(crypto.CompressPubkey(&c.EphemeralPrivateKey.PublicKey))))
	r.Header.Set("x-certificate", c.Message)
	r.Header.Set("x-certificate-signature", c.Signature)
	r.Header.Set("x-timestamp", timestamp)

	return nil
}

func buildPostRequest(c *ephemeralkey.Credentials) (*http.Request, error) {
	text := "{\"param1\":\"data1\",\"param2\":\"data2\"}"

	req, err := http.NewRequest("POST", "http://market.decentraland.org/api/v1/marketplace", strings.NewReader(text))
	if err != nil {
		return nil, err
	}

	if err := addHeaders(c, req); err != nil {
		return nil, err
	}

	return req, err
}

func buildGetRequest(c *ephemeralkey.Credentials) (*http.Request, error) {
	req, err := http.NewRequest("GET", "http://market.decentraland.org/api/v1/marketplace?something=something", nil)
	if err != nil {
		return nil, err
	}

	if err := addHeaders(c, req); err != nil {
		return nil, err
	}

	return req, err
}

func buildMessageToVerify(r *http.Request, timeStamp string) ([]byte, error) {
	method := r.Method
	url := r.URL.String()

	b, err := utils.ReadRequestBody(r)
	if err != nil {
		return nil, err
	}

	toSign := []byte(method)
	toSign = append(toSign, []byte(url)...)
	toSign = append(toSign, []byte(timeStamp)...)
	if b != nil {
		toSign = append(toSign, b...)
	}
	result := sha256.Sum256(toSign)
	return result[:], nil
}
