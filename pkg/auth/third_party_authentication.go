package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/decentraland/auth-go/internal/utils"
	"github.com/dgrijalva/jwt-go"
	"math/big"
	"strings"
	"time"
)

const thirdPartyUserIdPattern = "public key derived address: (.*)"

type ThirdPartyStrategy struct {
	RequestLifeSpan int64
	TrustedKey      *ecdsa.PublicKey
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

func (s *ThirdPartyStrategy) Authenticate(r *AuthRequest) (bool, error) {
	cred := r.Credentials

	requiredCredentials := []string{HeaderIdentity, HeaderTimestamp, HeaderAccessToken, HeaderSignature, HeaderAuthType}
	if err := utils.ValidateRequiredCredentials(cred, requiredCredentials); err != nil {
		return false, err
	}

	if err := validateCertificateType(cred, "third-party"); err != nil {
		return false, err
	}

	tokens, err := utils.ParseTokensWithRegex(cred[HeaderIdentity], thirdPartyUserIdPattern)
	if err != nil {
		return false, err
	}

	if len(tokens) != 1 {
		return false, fmt.Errorf("unable to exctract required information from 'x-identity' header")
	}

	ephPbKey := tokens[0]

	if err = checkRequestExpiration(cred["x-timestamp"], s.RequestLifeSpan); err != nil {
		return false, err
	}

	if err = validateRequestSignature(r, ephPbKey); err != nil {
		return false, err
	}

	if err = validateAccessToken(cred[HeaderAccessToken], s.TrustedKey, ephPbKey); err != nil {
		return false, err
	}

	return true, nil
}

func ExtractAuthTokenPayload(token string) (*AccessTokenPayload, error) {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return nil, errors.New("invalid Access Token")
	}
	cStr, err := jwt.DecodeSegment(segments[1])
	if err != nil {
		return nil, fmt.Errorf("decoding Access Token error: %s", err.Error())
	}
	var payload AccessTokenPayload
	err = json.Unmarshal([]byte(cStr), &payload)
	if err != nil || !payload.isValid() {
		return nil, errors.New("invalid Access Token payload")
	}
	return &payload, nil
}
func validateAccessToken(token string, trustedKey *ecdsa.PublicKey, ephKey string) error {
	payload, err := ExtractAuthTokenPayload(token)
	if err != nil {
		return err
	}

	if strings.ToLower(ephKey) != strings.ToLower(payload.EphemeralKey) {
		return errors.New("access Token ephemeral Key does not match the request key")
	}

	if time.Now().Unix() > payload.Expiration {
		return errors.New("expired token")
	}

	if _, err := jwt.Parse(token, getKeyJWT(trustedKey.X, trustedKey.Y)); err != nil {
		return fmt.Errorf("error validating Access Token: %s", err.Error())
	}

	return nil
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
