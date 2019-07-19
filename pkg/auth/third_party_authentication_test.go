package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"
)

const validEphKey = "0x0123456789012345678901234567890123456789"
const userID = "email|userID"

func TestValidateAccessToken(t *testing.T) {
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubKey := &serverKey.PublicKey

	for _, tc := range validateAccessTokenTC {
		t.Run(tc.name, func(t *testing.T) {
			tkn, errTkn := tc.tokenGenerator(serverKey)
			require.NoError(t, errTkn)
			_, err := validateAccessToken(tkn, pubKey, tc.ephemeralKey)

			tc.resultEvaluation(err, t)
		})
	}
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

var validateAccessTokenTC = []accessTokenTestCase{
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

func generateAccessToken(serverKey *ecdsa.PrivateKey, ephKey string, userID string, expiration int64) (string, error) {
	claims := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"user_id":       userID,
		"ephemeral_key": ephKey,
		"version":       "1.0",
		"exp":           expiration,
	})

	return claims.SignedString(serverKey)
}
