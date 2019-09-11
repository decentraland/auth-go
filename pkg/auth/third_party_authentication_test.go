package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/decentraland/auth-go/pkg/ephemeral"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validEphKey = "0x0123456789012345678901234567890123456789"
const userID = "email|userID"

const basicRequestBody = "{\"param1\":\"data1\",\"param2\":\"data2\"}"

func TestValidateCredentials(t *testing.T) {

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for _, tc := range validateCredentialsTc {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ephKey, err := ephemeral.NewEphemeralKey(&ephemeral.EphemeralKeyConfig{})
			require.NoError(t, err)

			pubKey := hexutil.Encode(crypto.CompressPubkey(&ephKey.PrivateKey.PublicKey))

			accessToken, err := generateAccessToken(serverKey, pubKey, userID, time.Now().Add(time.Second*10).Unix())
			require.NoError(t, err)

			v := &ThirdPartyStrategy{RequestTolerance: tc.tolerance, TrustedKey: &serverKey.PublicKey}

			req, err := buildAuthRequest()
			require.NoError(t, err)
			err = ephKey.AddRequestHeaders(req, accessToken)
			require.NoError(t, err)

			if tc.modifiedHeaders != nil {
				for header, val := range tc.modifiedHeaders {
					req.Header.Set(header, val)
				}
			}

			r, err := MakeFromHTTPRequest(req, "http://market.decentraland.org")
			if err != nil {
				t.Fail()
			}
			_, err = v.Authenticate(r)
			tc.resultAssertion(t, err, tc.errorMessage)
		})
	}
}

func TestValidateAccessToken(t *testing.T) {
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubKey := &serverKey.PublicKey

	for _, tc := range validateAccessTokenTC {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tkn, errTkn := tc.tokenGenerator(serverKey)
			require.NoError(t, errTkn)
			_, err := validateAccessToken(tkn, pubKey, tc.ephemeralKey)

			tc.resultEvaluation(err, t)
		})
	}
}

func TestCheckRequestTimestamp(t *testing.T) {
	var tolerance = int64(1000)

	// Within tolerance in the past
	err := checkRequestExpiration(strconv.Itoa(int(time.Now().Unix()-999)), tolerance)
	require.NoError(t, err)

	// Within tolerance in the future
	err = checkRequestExpiration(strconv.Itoa(int(time.Now().Unix()+999)), tolerance)
	require.NoError(t, err)

	// Outside tolerance in the future
	err = checkRequestExpiration(strconv.Itoa(int(time.Now().Unix()+1001)), tolerance)
	require.Error(t, err)

	// Outside tolerance in the past
	err = checkRequestExpiration(strconv.Itoa(int(time.Now().Unix()-1001)), tolerance)
	require.Error(t, err)
}

func TestDecodeUrlPath(t *testing.T) {
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ephKey, err := ephemeral.NewEphemeralKey(&ephemeral.EphemeralKeyConfig{})
	require.NoError(t, err)

	pubKey := hexutil.Encode(crypto.CompressPubkey(&ephKey.PrivateKey.PublicKey))

	accessToken, err := generateAccessToken(serverKey, pubKey, userID, time.Now().Add(time.Second*10).Unix())
	require.NoError(t, err)

	v := &ThirdPartyStrategy{RequestTolerance: 100000, TrustedKey: &serverKey.PublicKey}

	text := basicRequestBody
	req, err := http.NewRequest(
		"POST", "http://market.decentraland.org/api/v1/this will|be-encoded", strings.NewReader(text))

	require.NoError(t, err)

	err = ephKey.AddRequestHeaders(req, accessToken)
	require.NoError(t, err)

	r, err := MakeFromHTTPRequest(req, "http://market.decentraland.org")
	require.NoError(t, err)

	_, err = v.Authenticate(r)
	require.NoError(t, err)
}

func resultOk(err error, t *testing.T) {
	assert.Nil(t, err, "unexpected error")
}

func evaluateError(message string) func(err error, t *testing.T) {
	return func(err error, t *testing.T) {
		assert.NotNil(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), message))
	}
}

type accessTokenTestCase struct {
	name             string
	ephemeralKey     string
	tokenGenerator   func(serverKey *ecdsa.PrivateKey) (string, error)
	resultEvaluation func(err error, t *testing.T)
}

var validateAccessTokenTC = []accessTokenTestCase{ //nolint
	{
		name:         "Valid Token",
		ephemeralKey: validEphKey,
		tokenGenerator: func(serverKey *ecdsa.PrivateKey) (s string, e error) {
			return generateAccessToken(serverKey, validEphKey, userID, time.Now().Add(time.Second*10).Unix())
		},
		resultEvaluation: resultOk,
	},
	{
		name:         "Expired Token",
		ephemeralKey: validEphKey,
		tokenGenerator: func(serverKey *ecdsa.PrivateKey) (s string, e error) {
			return generateAccessToken(serverKey, validEphKey, userID, time.Now().Add(time.Second*-10).Unix())
		},
		resultEvaluation: evaluateError("expired token"),
	},
	{
		name:         "Invalid format Token",
		ephemeralKey: validEphKey,
		tokenGenerator: func(_ *ecdsa.PrivateKey) (s string, e error) {
			return "notTheValidFormat", nil
		},
		resultEvaluation: evaluateError("invalid token format"),
	},
	{
		name:         "Invalid Token Payload",
		ephemeralKey: validEphKey,
		tokenGenerator: func(serverKey *ecdsa.PrivateKey) (s string, e error) {
			claims := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
				"user_id": userID,
			})
			return claims.SignedString(serverKey)
		},
		resultEvaluation: evaluateError("access token payload missing required claims"),
	},
	{
		name:         "Wrong Ephemeral Key",
		ephemeralKey: validEphKey,
		tokenGenerator: func(serverKey *ecdsa.PrivateKey) (s string, e error) {
			return generateAccessToken(serverKey, "00000000", userID, time.Now().Add(time.Second*10).Unix())
		},
		resultEvaluation: evaluateError("access Token ephemeral Key does not match the request key"),
	},
	{
		name:         "Invalid Entity Public Key",
		ephemeralKey: validEphKey,
		tokenGenerator: func(_ *ecdsa.PrivateKey) (s string, e error) {
			serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return "", err
			}
			return generateAccessToken(serverKey, validEphKey, userID, time.Now().Add(time.Second*10).Unix())
		},
		resultEvaluation: evaluateError("error validating Access Token"),
	},
}

func generateAccessToken(serverKey *ecdsa.PrivateKey, ephKey string, userID string, expiration int64) (string, error) { //nolint
	claims := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"user_id":       userID,
		"ephemeral_key": ephKey,
		"version":       "1.0",
		"exp":           expiration,
	})

	return claims.SignedString(serverKey)
}

type validateCredentialsData struct {
	name            string
	tolerance       int64
	errorMessage    string
	modifiedHeaders map[string]string
	resultAssertion func(t *testing.T, err error, expectedMsg string)
}

func assertErrorMessage(t *testing.T, err error, expectedMsg string) {
	assert.NotNil(t, err)
	assert.Equal(t, expectedMsg, err.Error(),
		fmt.Sprintf("Expected Message: '%s'. Got: '%s'", expectedMsg, err.Error()))
}

func assertResultOk(t *testing.T, err error, _ string) {
	if err != nil {
		t.Fail()
	}
}

var validateCredentialsTc = []validateCredentialsData{ //nolint
	{
		name:            "Valid Credentials",
		tolerance:       10000,
		resultAssertion: assertResultOk,
	},
	{
		name:            "Expired AuthRequest",
		tolerance:       -1,
		errorMessage:    "request expired",
		resultAssertion: assertErrorMessage,
	},
	{
		name:      "Invalid Timestamp",
		tolerance: 10000,
		modifiedHeaders: map[string]string{
			HeaderTimestamp: "This is not a timestamp"},
		errorMessage:    "invalid timestamp",
		resultAssertion: assertErrorMessage,
	},
	{
		name:      "Invalid identity header",
		tolerance: 10000,
		modifiedHeaders: map[string]string{
			HeaderIdentity: "not the identity header"},
		errorMessage:    "malformed 'x-identity' header: not the identity header",
		resultAssertion: assertErrorMessage,
	},
	{
		name:      "Fail request way into future",
		tolerance: 1000,
		modifiedHeaders: map[string]string{
			HeaderTimestamp: strconv.FormatInt(time.Now().Unix()+15000, 10)},
		errorMessage:    "request expired",
		resultAssertion: assertErrorMessage,
	},
}

func buildAuthRequest() (*http.Request, error) {
	text := basicRequestBody

	return http.NewRequest(
		"POST", "http://market.decentraland.org/api/v1/marketplace", strings.NewReader(text))
}
