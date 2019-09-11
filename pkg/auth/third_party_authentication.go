package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/decentraland/auth-go/internal/utils"
	"github.com/dgrijalva/jwt-go"
)

const thirdPartyUserIDPattern = "public key derived address: (.*)"

// ThirdPartyStrategy strategy to validate JWT is signed by a trusted third party
type ThirdPartyStrategy struct {
	RequestTolerance int64
	TrustedKey       *ecdsa.PublicKey
}

// AccessTokenPayload represents the information in the JWT payload
type AccessTokenPayload struct {
	EphemeralKey string `json:"ephemeral_key"`
	Expiration   int64  `json:"exp"`
	UserID       string `json:"user_id"`
	Version      string `json:"version"`
}

func (a AccessTokenPayload) isValid() bool {
	return a.EphemeralKey != "" && a.Expiration > 0 && a.UserID != "" && a.Version != ""
}

// Authenticate check if the JWT is signed by a trusted third party
func (s *ThirdPartyStrategy) Authenticate(r *AuthRequest) (Result, error) {
	cred := r.Credentials
	output := NewResultOutput()
	requiredCredentials := []string{HeaderIdentity, HeaderTimestamp, HeaderAccessToken, HeaderSignature}
	if err := utils.ValidateRequiredCredentials(cred, requiredCredentials); err != nil {
		return output, MissingCredentialsError{err.Error()}
	}

	tokens, err := utils.ParseTokensWithRegex(cred[HeaderIdentity], thirdPartyUserIDPattern)
	if err != nil {
		return output, err
	}

	if len(tokens) != 1 {
		return output, InvalidCredentialError{"unable to extract required information from 'x-identity' header"}
	}

	ephPbKey := tokens[0]

	if err = checkRequestExpiration(cred["x-timestamp"], s.RequestTolerance); err != nil {
		return output, err
	}

	if err = validateRequestSignature(r, ephPbKey); err != nil {
		return output, err
	}

	tkn, err := validateAccessToken(cred[HeaderAccessToken], s.TrustedKey, ephPbKey)
	if err != nil {
		return output, err
	}

	output.AddUserID(tkn.UserID)
	return output, nil
}

func validateAccessToken(token string, trustedKey *ecdsa.PublicKey, ephKey string) (*AccessTokenPayload, error) {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return nil, InvalidAccessTokenError{"invalid token format", TokenFormatError}
	}

	seg, err := jwt.DecodeSegment(segments[1])
	if err != nil {
		return nil, InvalidAccessTokenError{fmt.Sprintf("decoding Access Token error: %s", err.Error()), PayloadFormatError}
	}

	var payload AccessTokenPayload
	err = json.Unmarshal(seg, &payload)
	if err != nil || !payload.isValid() {
		return nil, InvalidAccessTokenError{"access token payload missing required claims", MissingClaimsError}
	}

	if !strings.EqualFold(ephKey, payload.EphemeralKey) {
		return nil, InvalidAccessTokenError{"access Token ephemeral Key does not match the request key", EphKeyMatchError}
	}

	if time.Now().Unix() > payload.Expiration {
		return nil, InvalidAccessTokenError{"expired token", ExpiredTokenError}
	}

	if _, err := jwt.Parse(token, getKeyJWT(trustedKey.X, trustedKey.Y)); err != nil {
		return nil, InvalidAccessTokenError{fmt.Sprintf("error validating Access Token: %s", err.Error()), InvalidTokenError}
	}

	return &payload, nil
}

func getKeyJWT(x *big.Int, y *big.Int) func(token *jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("worng signing method")
		}
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}, nil
	}
}

// Validates that the signature sent in the request was generated for the current request
func validateRequestSignature(r *AuthRequest, pubKey string) error {
	cred := r.Credentials
	msg, err := r.Hash()
	if err != nil {
		return err
	}

	if err = validateSignature(cred["x-signature"], msg, pubKey); err != nil {
		return err
	}
	return nil
}

// Verifies  that the given pubkey created signature over message.
func validateSignature(signature string, message []byte, pubKey string) error {
	sigBytes, err := hexutil.Decode(utils.FormatHexString(signature))
	if err != nil {
		return InvalidCredentialError{fmt.Sprintf("unable to decode signature: %s", err.Error())}
	}

	key, err := hexutil.Decode(utils.FormatHexString(pubKey))
	if err != nil {
		return InvalidCredentialError{fmt.Sprintf("unable to decode publickey: %s", err.Error())}
	}

	if !secp256k1.VerifySignature(key, message, sigBytes) {
		return InvalidRequestSignatureError{"invalid Signature"}
	}
	return nil
}

// Verifies request expiration
func checkRequestExpiration(timestamp string, ttl int64) error {
	t, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return InvalidCredentialError{"invalid timestamp"}
	}
	now := time.Now().Unix()
	if abs(now-t) > ttl {
		return ExpiredRequestError{"request expired"}
	}
	return nil
}

func abs(v int64) int64 {
	if v > 0 {
		return v
	}
	return -v
}

// InvalidAccessTokenError is a validation error in the JWT
type InvalidAccessTokenError struct {
	message   string
	ErrorCode TokenValidationCode
}

func (e InvalidAccessTokenError) Error() string {
	return e.message
}

// TokenValidationCode JWT error code
type TokenValidationCode int

const (
	// TokenFormatError JWT is malformed
	TokenFormatError TokenValidationCode = 0
	// PayloadFormatError JWT payload section is invalid
	PayloadFormatError TokenValidationCode = 1
	// MissingClaimsError JWT payload is missing a required element
	MissingClaimsError TokenValidationCode = 2
	// EphKeyMatchError JWT ephKey do not match the key used to sign the request
	EphKeyMatchError TokenValidationCode = 3
	// ExpiredTokenError JWT expired
	ExpiredTokenError TokenValidationCode = 4
	// InvalidTokenError JWT is invalid
	InvalidTokenError TokenValidationCode = 5
)
