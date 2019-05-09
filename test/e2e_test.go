package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/decentraland/auth-go/internal/ethereum"
	"github.com/decentraland/auth-go/internal/utils"
	"github.com/decentraland/auth-go/pkg/auth"
	"github.com/decentraland/auth-go/pkg/authentication"
	"github.com/decentraland/auth-go/pkg/authorization"
	"github.com/decentraland/auth-go/pkg/ephemeral"
	"github.com/dgrijalva/jwt-go"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	r2 "math/rand"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

var runIntegrationTests = os.Getenv("RUN_IT") == "true"

func TestEphemeralKeys(t *testing.T) {
	if !runIntegrationTests {
		t.Skip("Skipping integration test. To run it set RUN_IT=true")
	}

	eth := os.Getenv("ETH_NODE")
	pass := os.Getenv("PASSPHRASE")

	c, err := ethereum.NewEthClient(eth)
	if err != nil {
		t.Error(err.Error())
	}

	acc, err := c.GetDefaultAccount()

	if err != nil {
		t.Error(err.Error())
	}

	accInfo := &ephemeral.EthAccountInfo{TokenAddress: "0x12345", Account: acc, Passphrase: pass}
	credential, err := ephemeral.GenerateEthBasedCredential(accInfo, c, 10)

	assert.Nil(t, err)
	assert.NotNil(t, credential)

	req := buildPostRequest()

	if err := credential.AddRequestHeaders(req); err != nil {
		t.Error(err.Error())
	}

	dclApi := os.Getenv("DCL_API")

	checkRequest(t, req, &authentication.SelfGrantedStrategy{RequestLifeSpan: 10}, authorization.NewInviteStrategy(dclApi))

	get := buildGetRequest()

	if err := credential.AddRequestHeaders(get); err != nil {
		t.Error(err.Error())
	}

	checkRequest(t, get, &authentication.SelfGrantedStrategy{RequestLifeSpan: 10}, authorization.NewInviteStrategy(dclApi))
}

type thirdPartyTestCase struct {
	name              string
	credentialTTL     int
	accessTokenTTL    time.Duration
	requestTTL        int64
	request           *http.Request
	tokenGen          func(serverKey *ecdsa.PrivateKey, ephKey string, duration time.Duration) (string, error)
	alternativePubKey *ecdsa.PublicKey
	wait              func()
	resultAssertion   func(ok bool, err error, t *testing.T)
}

var tpTable = []thirdPartyTestCase{
	{
		name:            "Valid Credentials - POST",
		credentialTTL:   10,
		accessTokenTTL:  60,
		requestTTL:      1000,
		tokenGen:        generateAccessToken,
		request:         buildPostRequest(),
		resultAssertion: thirdPartyAssertOk,
	},
	{
		name:            "Valid Credentials - GET",
		credentialTTL:   10,
		accessTokenTTL:  60,
		requestTTL:      1000,
		tokenGen:        generateAccessToken,
		request:         buildGetRequest(),
		resultAssertion: thirdPartyAssertOk,
	}, {
		name:           "Invalid Format Access Token",
		credentialTTL:  10,
		accessTokenTTL: 60,
		requestTTL:     1000,
		tokenGen: func(serverKey *ecdsa.PrivateKey, ephKey string, duration time.Duration) (s string, e error) {
			return "*.*.*", nil
		},
		request:         buildPostRequest(),
		resultAssertion: thirdPartyAssertError("decoding Access Token error"),
	}, {
		name:            "Invalid Data Access Token",
		credentialTTL:   10,
		accessTokenTTL:  60,
		requestTTL:      1000,
		tokenGen:        missingDataToken,
		request:         buildPostRequest(),
		resultAssertion: thirdPartyAssertError("invalid Access Token payload"),
	}, {
		name:              "Invalid Entity public Key",
		credentialTTL:     10,
		accessTokenTTL:    60,
		requestTTL:        1000,
		tokenGen:          generateAccessToken,
		alternativePubKey: getRandomKey(),
		request:           buildPostRequest(),
		resultAssertion:   thirdPartyAssertError("error validating Access Token"),
	}, {
		name:            "Expired Request",
		credentialTTL:   10,
		accessTokenTTL:  60,
		requestTTL:      1,
		tokenGen:        generateAccessToken,
		request:         buildPostRequest(),
		resultAssertion: thirdPartyAssertError("request expired"),
		wait:            wait(3 * time.Second),
	},
	{
		name:            "Expired Access Token",
		credentialTTL:   10,
		accessTokenTTL:  1,
		requestTTL:      1000,
		tokenGen:        generateAccessToken,
		request:         buildPostRequest(),
		resultAssertion: thirdPartyAssertError("expired token"),
		wait:            wait(3 * time.Second),
	},
}

func TestThirdPartyKeys(t *testing.T) {
	for _, tc := range tpTable {
		t.Run(tc.name, func(t *testing.T) {
			serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Error(err.Error())
			}
			credential, err := ephemeral.GenerateSimpleCredential(tc.credentialTTL)
			if err != nil {
				t.Error(err.Error())
			}

			accessToken, err := tc.tokenGen(serverKey, getAddressFromKey(&credential.EphemeralPrivateKey.PublicKey), tc.accessTokenTTL)
			if err != nil {
				t.Error(err.Error())
			}
			req := tc.request
			if err := credential.AddRequestHeaders(req, accessToken); err != nil {
				t.Error(err.Error())
			}

			key := &serverKey.PublicKey
			if tc.alternativePubKey != nil {
				key = tc.alternativePubKey
			}

			authHandler := auth.NewAuthProvider(
				&authentication.ThirdPartyStrategy{RequestLifeSpan: tc.requestTTL, TrustedKey: key},
				&authorization.AllowAllStrategy{})

			r, err := auth.MakeFromHttpRequest(req, "http://market.decentraland.org/")
			if err != nil {
				t.Fail()
			}

			if tc.wait != nil {
				tc.wait()
			}

			ok, err := authHandler.ApproveRequest(r)

			tc.resultAssertion(ok, err, t)

		})
	}
}

var noHttpRequestTable = []thirdPartyTestCase{
	{
		name:            "Valid Credentials",
		credentialTTL:   10,
		accessTokenTTL:  60,
		requestTTL:      1000,
		tokenGen:        generateAccessToken,
		resultAssertion: thirdPartyAssertOk,
	}, {
		name:           "Invalid Format Access Token",
		credentialTTL:  10,
		accessTokenTTL: 60,
		requestTTL:     1000,
		tokenGen: func(serverKey *ecdsa.PrivateKey, ephKey string, duration time.Duration) (s string, e error) {
			return "*.*.*", nil
		},
		resultAssertion: thirdPartyAssertError("decoding Access Token error"),
	}, {
		name:            "Invalid Data Access Token",
		credentialTTL:   10,
		accessTokenTTL:  60,
		requestTTL:      1000,
		tokenGen:        missingDataToken,
		resultAssertion: thirdPartyAssertError("invalid Access Token payload"),
	}, {
		name:              "Invalid Entity public Key",
		credentialTTL:     10,
		accessTokenTTL:    60,
		requestTTL:        1000,
		tokenGen:          generateAccessToken,
		alternativePubKey: getRandomKey(),
		resultAssertion:   thirdPartyAssertError("error validating Access Token"),
	}, {
		name:            "Expired Request",
		credentialTTL:   10,
		accessTokenTTL:  60,
		requestTTL:      1,
		tokenGen:        generateAccessToken,
		resultAssertion: thirdPartyAssertError("request expired"),
		wait:            wait(3 * time.Second),
	},
	{
		name:            "Expired Access Token",
		credentialTTL:   10,
		accessTokenTTL:  1,
		requestTTL:      1000,
		tokenGen:        generateAccessToken,
		resultAssertion: thirdPartyAssertError("expired token"),
		wait:            wait(3 * time.Second),
	},
}

func TestThirdPartyKeysNoHTTPRequest(t *testing.T) {
	for _, tc := range noHttpRequestTable {
		t.Run(tc.name, func(t *testing.T) {
			serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Error(err.Error())
			}
			credential, err := ephemeral.GenerateSimpleCredential(tc.credentialTTL)
			if err != nil {
				t.Error(err.Error())
			}

			accessToken, err := tc.tokenGen(serverKey, getAddressFromKey(&credential.EphemeralPrivateKey.PublicKey), tc.accessTokenTTL)
			if err != nil {
				t.Error(err.Error())
			}

			msg := randomMessage(50)

			now := time.Now().Unix()

			msgHash, err := utils.GenerateMessageHash(msg, now)
			if err != nil {
				t.Error(err.Error())
			}

			fields, err := credential.MakeCredentials(msgHash, accessToken, now)
			if err != nil {
				t.Error(err.Error())
			}

			key := &serverKey.PublicKey
			if tc.alternativePubKey != nil {
				key = tc.alternativePubKey
			}
			authHandler := auth.NewAuthProvider(
				&authentication.ThirdPartyStrategy{RequestLifeSpan: tc.requestTTL, TrustedKey: key},
				&authorization.AllowAllStrategy{})

			r := &auth.AuthRequest{Credentials: fields, Content: msg}

			if tc.wait != nil {
				tc.wait()
			}

			ok, err := authHandler.ApproveRequest(r)

			tc.resultAssertion(ok, err, t)

		})
	}
}

func getAddressFromKey(pk *ecdsa.PublicKey) string {
	return hexutil.Encode(crypto.CompressPubkey(pk))
}

func generateAccessToken(serverKey *ecdsa.PrivateKey, ephKey string, duration time.Duration) (string, error) {
	claims := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"user_id":       "userId",
		"ephemeral_key": ephKey,
		"version":       "1.0",
		"exp":           time.Now().Add(time.Second * duration).Unix(),
	})

	return claims.SignedString(serverKey)
}

func missingDataToken(serverKey *ecdsa.PrivateKey, _ string, duration time.Duration) (string, error) {
	claims := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"user_id": "userId",
		"version": "1.0",
		"exp":     time.Now().Add(time.Second * duration).Unix(),
	})

	return claims.SignedString(serverKey)
}

func wait(d time.Duration) func() {
	return func() {
		time.Sleep(d)
	}
}

func thirdPartyAssertOk(ok bool, err error, t *testing.T) {
	assert.True(t, ok)
	assert.Nil(t, err)
}

func thirdPartyAssertError(message string) func(ok bool, err error, t *testing.T) {
	return func(ok bool, err error, t *testing.T) {
		assert.NotNil(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), message))
	}
}

func checkRequest(t *testing.T, req *http.Request, authn auth.AuthenticationStrategy, authz auth.AuthorizationStrategy) {
	authHandler := auth.NewAuthProvider(authn, authz)

	r, err := auth.MakeFromHttpRequest(req, "http://market.decentraland.org/")
	if err != nil {
		t.Fail()
	}

	validation, err := authHandler.ApproveRequest(r)
	if err != nil {
		t.Error(err.Error())
	}

	assert.True(t, validation)
}

func buildPostRequest() *http.Request {
	text := "{\"param1\":\"data1\",\"param2\":\"data2\"}"

	req, _ := http.NewRequest("POST", "http://market.decentraland.org/api/v1/marketplace", strings.NewReader(text))

	return req
}

func buildGetRequest() *http.Request {
	req, _ := http.NewRequest("GET", "http://market.decentraland.org/api/v1/marketplace?something=something", nil)
	return req
}

func randomMessage(length int) []byte {
	const charset = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	seededRand := r2.New(r2.NewSource(time.Now().UnixNano()))

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}

	return b
}

func getRandomKey() *ecdsa.PublicKey {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &key.PublicKey
}
