package auth

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"github.com/decentraland/auth-go/pkg/commons"
	"net/http"
	"strings"
)

type AuthProvider interface {
	ApproveRequest(r *AuthRequest) (bool, error)
}

type AuthRequest struct {
	Credentials map[string]string
	Content     []byte
	Method      string
	URL         string
}

type AuthenticationStrategy interface {
	Authenticate(r *AuthRequest) (bool, error)
}

type AuthorizationStrategy interface {
	Authorize(r *AuthRequest) (bool, error)
}

type authProviderImpl struct {
	authn AuthenticationStrategy
	authz AuthorizationStrategy
}

type ProviderConfig struct {
	Authn AuthenticationStrategy
	Authz AuthorizationStrategy
}

func NewAuthProvider(authn AuthenticationStrategy, authz AuthorizationStrategy) (AuthProvider, error) {
	if authn == nil && authz == nil {
		return nil, errors.New("missing required strategy")
	}
	return &authProviderImpl{
		authn: authn,
		authz: authz,
	}, nil
}

type ThirdPartyProviderConfig struct {
	Authn           AuthenticationStrategy
	Authz           AuthorizationStrategy
	RequestLifeSpan int64
	TrustedKey      *ecdsa.PublicKey
}

func NewThirdPartyAuthProvider(config *ThirdPartyProviderConfig) (AuthProvider, error) {
	authn := config.Authn
	if authn == nil {
		if config.TrustedKey == nil {
			return nil, errors.New("missing required trusted key")
		}
		authn = &ThirdPartyStrategy{RequestTolerance: config.RequestLifeSpan, TrustedKey: config.TrustedKey}
	}

	authz := config.Authz
	if authz == nil {
		authz = &AllowAllAuthzStrategy{}
	}
	return NewAuthProvider(authn, authz)
}

// Authenticate and Authorize request based on the AuthorizationStrategy
func (ah *authProviderImpl) ApproveRequest(r *AuthRequest) (bool, error) {
	auth, err := ah.authn.Authenticate(r)
	if err != nil {
		return false, AuthenticationError{err.Error()}
	}

	if !auth {
		return auth, nil
	}

	aut, err := ah.authz.Authorize(r)
	if err != nil {
		return false, AuthorizationError{err.Error()}
	}
	return aut, nil
}

type AuthenticationError struct {
	cause string
}
type AuthorizationError struct {
	cause string
}

func (e AuthenticationError) Error() string {
	return e.cause
}

func (e AuthorizationError) Error() string {
	return e.cause
}

// Retrieves a SHA256 checksum of teh request content
func (r *AuthRequest) Hash() ([]byte, error) {
	method := r.Method
	url := r.URL
	timestamp := r.Credentials["x-timestamp"]

	toSign := []byte{}
	if len(method) > 0 {
		toSign = append(toSign, []byte(method)...)
	}
	if len(url) > 0 {
		toSign = append(toSign, []byte(url)...)
	}
	if len(timestamp) > 0 {
		toSign = append(toSign, []byte(timestamp)...)
	}

	if r.Content != nil {
		toSign = append(toSign, r.Content...)
	}

	result := sha256.Sum256(toSign)
	return result[:], nil
}

// Generate a AuthRequest from a http.Request
func MakeFromHttpRequest(r *http.Request, publicBaseUrl string) (*AuthRequest, error) {
	credentials := make(map[string]string)
	for key, value := range r.Header {
		credentials[strings.ToLower(key)] = value[0]
	}

	content, err := commons.ReadRequestBody(r)
	if err != nil {
		return nil, err
	}

	return &AuthRequest{
		Credentials: credentials,
		Content:     content,
		Method:      r.Method,
		URL:         buildUrl(publicBaseUrl, r.URL.RequestURI()),
	}, nil
}

const (
	HeaderIdentity      = "x-identity"
	HeaderTimestamp     = "x-timestamp"
	HeaderAccessToken   = "x-access-token"
	HeaderSignature     = "x-signature"
	HeaderAuthType      = "x-auth-type"
	HeaderCert          = "x-certificate"
	HeaderCertSignature = "x-certificate-signature"
)
