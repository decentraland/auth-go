package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	r2 "math/rand"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/decentraland/auth-go/internal/ethereum"
	"github.com/decentraland/auth-go/pkg/auth"
	"github.com/decentraland/auth-go/pkg/ephemeral"
	"github.com/dgrijalva/jwt-go"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var runIntegrationTests = os.Getenv("RUN_IT") == "true" //nolint

const userID = "userID"

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
	ephemeralKey, err := ephemeral.GenerateEthEphemeralKey(accInfo, c, 10)

	assert.Nil(t, err)
	assert.NotNil(t, ephemeralKey)

	req := buildPostRequest()

	if err := ephemeralKey.AddRequestHeaders(req); err != nil {
		t.Error(err.Error())
	}

	dclAPI := os.Getenv("DCL_API")

	checkRequest(t, req, &auth.SelfGrantedStrategy{RequestTolerance: 10}, auth.NewInviteStrategy(dclAPI))

	get := buildGetRequest()

	if err := ephemeralKey.AddRequestHeaders(get); err != nil {
		t.Error(err.Error())
	}

	checkRequest(t, get, &auth.SelfGrantedStrategy{RequestTolerance: 10}, auth.NewInviteStrategy(dclAPI))
}

type thirdPartyTestCase struct {
	name              string
	accessTokenTTL    time.Duration
	requestTTL        int64
	request           *http.Request
	tokenGen          func(serverKey *ecdsa.PrivateKey, ephKey string, duration time.Duration) (string, error)
	alternativePubKey *ecdsa.PublicKey
	wait              func()
	resultAssertion   func(err error, t *testing.T)
}

var tpTable = []thirdPartyTestCase{ //nolint
	{
		name:            "Valid Credentials - POST",
		accessTokenTTL:  60,
		requestTTL:      1000,
		tokenGen:        generateAccessToken,
		request:         buildPostRequest(),
		resultAssertion: thirdPartyAssertOk,
	},
	{
		name:            "Valid Credentials - GET",
		accessTokenTTL:  60,
		requestTTL:      1000,
		tokenGen:        generateAccessToken,
		request:         buildGetRequest(),
		resultAssertion: thirdPartyAssertOk,
	}, {
		name:           "Invalid Format Access Token",
		accessTokenTTL: 60,
		requestTTL:     1000,
		tokenGen: func(serverKey *ecdsa.PrivateKey, ephKey string, duration time.Duration) (s string, e error) {
			return "*.*.*", nil
		},
		request:         buildPostRequest(),
		resultAssertion: thirdPartyAssertError("decoding Access Token error"),
	},
	{
		name:            "Invalid Data Access Token",
		accessTokenTTL:  60,
		requestTTL:      1000,
		tokenGen:        missingDataToken,
		request:         buildPostRequest(),
		resultAssertion: thirdPartyAssertError("access token payload missing required claims"),
	}, {
		name:              "Invalid Entity public Key",
		accessTokenTTL:    60,
		requestTTL:        1000,
		tokenGen:          generateAccessToken,
		alternativePubKey: getRandomKey(),
		request:           buildPostRequest(),
		resultAssertion:   thirdPartyAssertError("error validating Access Token"),
	}, {
		name:            "Expired Request",
		accessTokenTTL:  60,
		requestTTL:      1,
		tokenGen:        generateAccessToken,
		request:         buildPostRequest(),
		resultAssertion: thirdPartyAssertError("request expired"),
		wait:            wait(4 * time.Second),
	},
	{
		name:            "Expired Access Token",
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
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Error(err.Error())
			}
			ephemeralKey, err := ephemeral.NewEphemeralKey(&ephemeral.EphemeralKeyConfig{})
			if err != nil {
				t.Error(err.Error())
			}

			accessToken, err := tc.tokenGen(serverKey, getAddressFromKey(ephemeralKey.PublicKey()), tc.accessTokenTTL)
			if err != nil {
				t.Error(err.Error())
			}
			req := tc.request
			if addErr := ephemeralKey.AddRequestHeaders(req, accessToken); addErr != nil {
				t.Error(addErr.Error())
			}

			key := &serverKey.PublicKey
			if tc.alternativePubKey != nil {
				key = tc.alternativePubKey
			}

			authHandler, err := auth.NewThirdPartyAuthProvider(
				&auth.ThirdPartyProviderConfig{RequestLifeSpan: tc.requestTTL, TrustedKey: key})

			if err != nil {
				t.Fail()
			}

			r, err := auth.MakeFromHTTPRequest(req, "http://market.decentraland.org/")
			if err != nil {
				t.Fail()
			}

			if tc.wait != nil {
				tc.wait()
			}

			output, err := authHandler.ApproveRequest(r)

			tc.resultAssertion(err, t)
			if err == nil {
				assert.Equal(t, userID, output.GetUserID())
			}

		})
	}
}

var noHttpRequestTable = []thirdPartyTestCase{ //nolint
	{
		name:            "Valid Credentials",
		accessTokenTTL:  60,
		requestTTL:      1000,
		tokenGen:        generateAccessToken,
		resultAssertion: thirdPartyAssertOk,
	}, {
		name:           "Invalid Format Access Token",
		accessTokenTTL: 60,
		requestTTL:     1000,
		tokenGen: func(serverKey *ecdsa.PrivateKey, ephKey string, duration time.Duration) (s string, e error) {
			return "*.*.*", nil
		},
		resultAssertion: thirdPartyAssertError("decoding Access Token error"),
	}, {
		name:            "Invalid Data Access Token",
		accessTokenTTL:  60,
		requestTTL:      1000,
		tokenGen:        missingDataToken,
		resultAssertion: thirdPartyAssertError("access token payload missing required claims"),
	}, {
		name:              "Invalid Entity public Key",
		accessTokenTTL:    60,
		requestTTL:        1000,
		tokenGen:          generateAccessToken,
		alternativePubKey: getRandomKey(),
		resultAssertion:   thirdPartyAssertError("error validating Access Token"),
	}, {
		name:            "Expired Request",
		accessTokenTTL:  60,
		requestTTL:      1,
		tokenGen:        generateAccessToken,
		resultAssertion: thirdPartyAssertError("request expired"),
		wait:            wait(3 * time.Second),
	},
	{
		name:            "Expired Access Token",
		accessTokenTTL:  1,
		requestTTL:      1000,
		tokenGen:        generateAccessToken,
		resultAssertion: thirdPartyAssertError("expired token"),
		wait:            wait(3 * time.Second),
	},
}

func TestThirdPartyKeysNoHTTPRequest(t *testing.T) {
	for _, tc := range noHttpRequestTable {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Error(err.Error())
			}
			ephemeralKey, err := ephemeral.NewEphemeralKey(&ephemeral.EphemeralKeyConfig{})
			if err != nil {
				t.Error(err.Error())
			}

			accessToken, err := tc.tokenGen(serverKey, getAddressFromKey(ephemeralKey.PublicKey()), tc.accessTokenTTL)
			if err != nil {
				t.Error(err.Error())
			}

			msg := randomMessage(50)

			fields, err := ephemeralKey.MakeCredentials(msg, accessToken)
			if err != nil {
				t.Error(err.Error())
			}

			key := &serverKey.PublicKey
			if tc.alternativePubKey != nil {
				key = tc.alternativePubKey
			}
			authHandler, err := auth.NewThirdPartyAuthProvider(
				&auth.ThirdPartyProviderConfig{RequestLifeSpan: tc.requestTTL, TrustedKey: key})
			if err != nil {
				t.Fail()
			}

			r := &auth.AuthRequest{Credentials: fields, Content: msg}

			if tc.wait != nil {
				tc.wait()
			}

			output, err := authHandler.ApproveRequest(r)

			tc.resultAssertion(err, t)
			if err == nil {
				assert.Equal(t, userID, output.GetUserID())
			}

		})
	}
}

func getAddressFromKey(pk *ecdsa.PublicKey) string {
	return hexutil.Encode(crypto.CompressPubkey(pk))
}

func generateAccessToken(serverKey *ecdsa.PrivateKey, ephKey string, duration time.Duration) (string, error) {
	claims := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"user_id":       userID,
		"ephemeral_key": ephKey,
		"version":       "1.0",
		"exp":           time.Now().Add(time.Second * duration).Unix(),
	})

	return claims.SignedString(serverKey)
}

func missingDataToken(serverKey *ecdsa.PrivateKey, _ string, duration time.Duration) (string, error) {
	claims := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"user_id": userID,
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

func thirdPartyAssertOk(err error, t *testing.T) {
	assert.Nil(t, err)
}

func thirdPartyAssertError(message string) func(err error, t *testing.T) {
	return func(err error, t *testing.T) {
		assert.NotNil(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), message))
	}
}

func checkRequest(t *testing.T, r *http.Request, authn auth.AuthenticationStrategy, authz auth.AuthorizationStrategy) {
	authHandler, err := auth.NewAuthProvider(authn, authz)
	require.NoError(t, err)

	req, err := auth.MakeFromHTTPRequest(r, "http://market.decentraland.org/")
	require.NoError(t, err)

	_, err = authHandler.ApproveRequest(req)
	require.NoError(t, err)
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
