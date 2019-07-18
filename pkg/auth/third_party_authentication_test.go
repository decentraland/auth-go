package auth

import (
	"github.com/decentraland/auth-go/pkg/keys"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

const validJWTAccessToken = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlcGhlbWVyYWxfa2V5IjoiMHgwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5IiwiZXhwIjo1MTUwMTcxOTk0LCJzZXJ2ZXJfaWQiOiJ0aGUgYXV0aCBzZXJ2ZXIiLCJ1c2VyX2lkIjoic2VydmljZVVzZXIxMjM0IiwidmVyc2lvbiI6IjEuMCJ9.at_2PBt-7gL4XCFQw7xTRZhoGnZCBJGFD0BTPdFPgCEWUxSVYKgoO56sMagKxfIRouapFzs277q7o0XsVKOZmw"
const validEphKey = "0x0123456789012345678901234567890123456789"
const validEntityPubKey = "0479b6379a4434e330496762f14d1bc5ca65d73fc79870413e6b2b7e85dd2af166cae53629125fb8a702b9f29747947e37a06ecc7a6ef63bd3f7fc2cba98b5d79f"

const expiredToken = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlcGhlbWVyYWxfa2V5IjoiMHgwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5IiwiZXhwIjoxNTUwMTc1MDY4LCJzZXJ2ZXJfaWQiOiJ0aGUgYXV0aCBzZXJ2ZXIiLCJ1c2VyX2lkIjoic2VydmljZVVzZXIxMjM0IiwidmVyc2lvbiI6IjEuMCJ9.K6f6ETxhci3YF7Kh1wNFIO_Aax41DfhbwSRHTkzt-cvsa8rdIDzg2BsQLNNAVGXgsKle_rxvrkXfF6q-0B37tA"
const invalidTokenContent = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
const wrongPubKey = "0495e8db73b3bd23a67291d51d12a24255af57870e72a6e992e8df6bd0c892741a65e6908f991a4fe6a146e3f233dd97004609a202470cda8053c3509ec4abc106"

func TestValidateAccessToken(t *testing.T) {
	for _, tc := range validateAccessTokenTC {
		t.Run(tc.name, func(t *testing.T) {
			k, _ := keys.ReadPublicKey(tc.entityKey)

			_, err := validateAccessToken(tc.accessToken, k, tc.ephemeralKey)

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
	accessToken      string
	entityKey        string
	resultEvaluation func(err error, t *testing.T)
}

var validateAccessTokenTC = []accessTokenTestCase{
	{
		name:             "Valid Token",
		ephemeralKey:     validEphKey,
		accessToken:      validJWTAccessToken,
		entityKey:        validEntityPubKey,
		resultEvaluation: resultOk,
	},
	{
		name:             "Expired Token",
		ephemeralKey:     validEphKey,
		accessToken:      expiredToken,
		entityKey:        validEntityPubKey,
		resultEvaluation: evaluateError("expired token"),
	},
	{
		name:             "Invalid format Token",
		ephemeralKey:     validEphKey,
		accessToken:      "notTheValidFormat",
		entityKey:        validEntityPubKey,
		resultEvaluation: evaluateError("invalid Access Token"),
	},
	{
		name:             "Invalid Token encoding",
		ephemeralKey:     validEphKey,
		accessToken:      "*.*.*",
		entityKey:        validEntityPubKey,
		resultEvaluation: evaluateError("decoding Access Token error"),
	}, {
		name:             "Invalid Token Payload",
		ephemeralKey:     validEphKey,
		accessToken:      invalidTokenContent,
		entityKey:        validEntityPubKey,
		resultEvaluation: evaluateError("invalid Access Token payload"),
	}, {
		name:             "Wrong Ephemeral Key",
		ephemeralKey:     "000000",
		accessToken:      validJWTAccessToken,
		entityKey:        validEntityPubKey,
		resultEvaluation: evaluateError("access Token ephemeral Key does not match the request key"),
	}, {
		name:             "Invalid Entity Public Key",
		ephemeralKey:     validEphKey,
		accessToken:      validJWTAccessToken,
		entityKey:        wrongPubKey,
		resultEvaluation: evaluateError("error validating Access Token"),
	},
}
