package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"github.com/decentraland/auth-go/internal/utils"
	"github.com/dgrijalva/jwt-go"
	"math/big"
	"strings"
	"time"
)

const thirdPartyUserIdPattern = "public key derived address: (.*)"

type ThirdPartyStrategy struct {
	RequestTolerance int64
	TrustedKey       *ecdsa.PublicKey
}

type AccessTokenPayload struct {
	EphemeralKey string `json:"ephemeral_key"`
	Expiration   int64  `json:"exp"`
	UserId       string `json:"user_id"`
	Version      string `json:"version"`
}

func (a AccessTokenPayload) isValid() bool {
	return a.EphemeralKey != "" && a.Expiration > 0 && a.UserId != "" && a.Version != ""
}

func (s *ThirdPartyStrategy) Authenticate(r *AuthRequest) (Result, error) {
	cred := r.Credentials
	output := NewResultOutput()
	requiredCredentials := []string{HeaderIdentity, HeaderTimestamp, HeaderAccessToken, HeaderSignature, HeaderAuthType}
	if err := utils.ValidateRequiredCredentials(cred, requiredCredentials); err != nil {
		return output, MissingCredentialsError{err.Error()}
	}

	if err := validateCertificateType(cred, "third-party"); err != nil {
		return output, err
	}

	tokens, err := utils.ParseTokensWithRegex(cred[HeaderIdentity], thirdPartyUserIdPattern)
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

	output.AddUserID(tkn.UserId)
	return output, nil
}

func validateAccessToken(token string, trustedKey *ecdsa.PublicKey, ephKey string) (*AccessTokenPayload, error) {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return nil, NewInvalidAccessToken("invalid token format", TokenFormatError)
	}

	cStr, err := jwt.DecodeSegment(segments[1])
	if err != nil {
		return nil, NewInvalidAccessToken(fmt.Sprintf("decoding Access Token error: %s", err.Error()), PayloadFormatError)
	}

	var payload AccessTokenPayload
	err = json.Unmarshal([]byte(cStr), &payload)
	if err != nil || !payload.isValid() {
		return nil, NewInvalidAccessToken("access token payload missing required claims", MissingClaimsError)
	}

	if strings.ToLower(ephKey) != strings.ToLower(payload.EphemeralKey) {
		return nil, NewInvalidAccessToken("access Token ephemeral Key does not match the request key", EphKeyMatchError)
	}

	if time.Now().Unix() > payload.Expiration {
		return nil, NewInvalidAccessToken("expired token", ExpiredTokenError)
	}

	if _, err := jwt.Parse(token, getKeyJWT(trustedKey.X, trustedKey.Y)); err != nil {
		return nil, NewInvalidAccessToken(fmt.Sprintf("error validating Access Token: %s", err.Error()), InvalidTokenError)
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

type InvalidAccessTokenError struct {
	message   string
	ErrorCode TokenValidationCode
}

func (e InvalidAccessTokenError) Error() string {
	return e.message
}

func NewInvalidAccessToken(msg string, code TokenValidationCode) InvalidAccessTokenError {
	return InvalidAccessTokenError{message: msg, ErrorCode: code}
}

type TokenValidationCode int

const (
	TokenFormatError   TokenValidationCode = 0
	PayloadFormatError TokenValidationCode = 1
	MissingClaimsError TokenValidationCode = 2
	EphKeyMatchError   TokenValidationCode = 3
	ExpiredTokenError  TokenValidationCode = 4
	InvalidTokenError  TokenValidationCode = 5
)
