package authentication

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/decentraland/auth-go/internal/utils"
	"github.com/decentraland/auth-go/pkg/auth"
	"github.com/dgrijalva/jwt-go"
	"math/big"
	"strings"
	"time"
)

const thirdPartyUserIdPattern = "public key derived address: (.*)"

type ThirdPartyStrategy struct {
	RequestLifeSpan int64
	TrustedEntities map[string]*ecdsa.PublicKey
}

type accessTokenPayload struct {
	EphemeralKey string `json:"ephemeral_key"`
	Expiration   int64  `json:"exp"`
	ServerId     string `json:"server_id"`
	UserId       string `json:"user_id"`
	Version      string `json:"version"`
}

func (a accessTokenPayload) isValid() bool {
	return a.EphemeralKey != "" && a.Expiration > 0 && a.ServerId != "" && a.UserId != "" && a.Version != ""
}

func (s *ThirdPartyStrategy) Authenticate(r *auth.AuthRequest) (bool, error) {
	cred := r.Credentials
	idHeader, err := utils.ExtractRequiredField(cred, "x-identity")
	if err != nil {
		return false, err
	}
	tokens, err := utils.ParseTokensWithRegex(idHeader, thirdPartyUserIdPattern)
	if err != nil {
		return false, err
	}

	if len(tokens) != 1 {
		return false, fmt.Errorf("unable to exctract required information from 'x-identity' header")
	}

	ephPbKey := tokens[0]

	if err = checkRequestExpiration(cred, s.RequestLifeSpan); err != nil {
		return false, err
	}

	if err = validateRequestSignature(r, ephPbKey); err != nil {
		return false, err
	}

	accessToken, err := utils.ExtractRequiredField(cred, "x-access-token")
	if err != nil {
		return false, err
	}

	if err = validateAccessToken(accessToken, s.TrustedEntities, ephPbKey); err != nil {
		return false, err
	}

	return true, nil
}

func validateAccessToken(token string, entities map[string]*ecdsa.PublicKey, ephKey string) error {
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return errors.New("invalid Access Token")
	}
	cStr, err := jwt.DecodeSegment(segments[1])
	if err != nil {
		return fmt.Errorf("decoding Access Token error: %s", err.Error())
	}
	var payload accessTokenPayload
	err = json.Unmarshal([]byte(cStr), &payload)
	if err != nil || !payload.isValid() {
		return errors.New("invalid Access Token payload")
	}

	if strings.ToLower(ephKey) != strings.ToLower(payload.EphemeralKey) {
		return errors.New("access Token ephemeral Key does not match the request key")
	}

	if time.Now().Unix() > payload.Expiration {
		return errors.New("expired token")
	}

	key, ok := entities[payload.ServerId]

	if !ok {
		return fmt.Errorf("unknown entity: %s", payload.ServerId)
	} else if _, err := jwt.Parse(token, getKeyJWT(key.X, key.Y)); err != nil {
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
