package auth

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/decentraland/auth-go/pkg/commons"
)

// AuthProvider auth provider contract
type AuthProvider interface { //nolint
	ApproveRequest(r *AuthRequest) (Result, error)
}

// AuthRequest request to validate
type AuthRequest struct { //nolint
	Credentials map[string]string
	Content     []byte
	Method      string
	URL         string
}

// AuthenticationStrategy authentication contract
type AuthenticationStrategy interface {
	Authenticate(r *AuthRequest) (Result, error)
}

// AuthorizationStrategy  authorization contract
type AuthorizationStrategy interface {
	Authorize(r *AuthRequest) (Result, error)
}

type authProviderImpl struct {
	authn AuthenticationStrategy
	authz AuthorizationStrategy
}

// ProviderConfig AuthProvider configuration
type ProviderConfig struct {
	Authn AuthenticationStrategy
	Authz AuthorizationStrategy
}

// NewAuthProvider retrieves a new AuthProvider
func NewAuthProvider(authn AuthenticationStrategy, authz AuthorizationStrategy) (AuthProvider, error) {
	if authn == nil && authz == nil {
		return nil, errors.New("missing required strategy")
	}
	return &authProviderImpl{
		authn: authn,
		authz: authz,
	}, nil
}

// ThirdPartyProviderConfig auth for third party signed tokens
type ThirdPartyProviderConfig struct {
	Authn           AuthenticationStrategy
	Authz           AuthorizationStrategy
	RequestLifeSpan int64
	TrustedKey      *ecdsa.PublicKey
}

//NewThirdPartyAuthProvider retrieves a new ThirdPartyProviderConfig
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

// ApproveRequest authenticates and authorizes request based on the AuthorizationStrategy
func (ah *authProviderImpl) ApproveRequest(r *AuthRequest) (Result, error) {
	output, err := ah.authn.Authenticate(r)
	if err != nil {
		return nil, err
	}

	aut, err := ah.authz.Authorize(r)
	if err != nil {
		return nil, err
	}

	output.AddAll(aut)

	return output, nil
}

// AuthenticationError fail to authenticate request
type AuthenticationError struct {
	cause string
}

// AuthorizationError fail to authorize request
type AuthorizationError struct {
	cause string
}

func (e AuthenticationError) Error() string {
	return e.cause
}

func (e AuthorizationError) Error() string {
	return e.cause
}

// Hash retrieves a SHA256 checksum of the request content
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

// MakeFromHTTPRequest generates a AuthRequest from a http.Request
func MakeFromHTTPRequest(r *http.Request, publicBaseURL string) (*AuthRequest, error) {
	credentials := make(map[string]string)
	for key, value := range r.Header {
		credentials[strings.ToLower(key)] = value[0]
	}

	content, err := commons.ReadRequestBody(r)
	if err != nil {
		return nil, err
	}

	path, err := url.QueryUnescape(r.URL.RequestURI())
	if err != nil {
		return nil, err
	}

	return &AuthRequest{
		Credentials: credentials,
		Content:     content,
		Method:      r.Method,
		URL:         buildURL(publicBaseURL, path),
	}, nil
}

const (
	// HeaderIdentity x-identity credential
	HeaderIdentity = "x-identity"
	// HeaderTimestamp x-timestamp credential
	HeaderTimestamp = "x-timestamp"
	// HeaderAccessToken x-access-token credential
	HeaderAccessToken = "x-access-token"
	// HeaderSignature x-signature credential
	HeaderSignature = "x-signature"
)

// Result auth process output
type Result map[string]interface{}

// GetUserID reads userID from result, if missing retrieves ""
func (r Result) GetUserID() string {
	id, ok := r["userID"]
	if !ok {
		return ""
	}
	return id.(string)
}

// AddUserID adds userID key
func (r Result) AddUserID(userID string) {
	r["userID"] = userID
}

// AddAll adds all elements from one result to this instance
func (r Result) AddAll(other Result) {
	if other != nil {
		for k, v := range other {
			r[k] = v
		}
	}
}

// NewResultOutput retrieves new auth.Result instance
func NewResultOutput() Result {
	return make(map[string]interface{})
}

// MissingCredentialsError a required credential si missing from request
type MissingCredentialsError struct {
	message string
}

func (e MissingCredentialsError) Error() string {
	return e.message
}

// InvalidCredentialError one of the credentials in the request is invalid
type InvalidCredentialError struct {
	message string
}

func (e InvalidCredentialError) Error() string {
	return e.message
}

// ExpiredRequestError request has expired
type ExpiredRequestError struct {
	message string
}

func (e ExpiredRequestError) Error() string {
	return e.message
}

// InvalidRequestSignatureError request signature is invalid
type InvalidRequestSignatureError struct {
	message string
}

func (e InvalidRequestSignatureError) Error() string {
	return e.message
}

// InvalidCertificateError certificate is invalid
type InvalidCertificateError struct {
	message string
}

func (e InvalidCertificateError) Error() string {
	return e.message
}

// AllowAllAuthzStrategy  authorize all requests
type AllowAllAuthzStrategy struct{}

// Authorize all requests
func (di *AllowAllAuthzStrategy) Authorize(r *AuthRequest) (Result, error) {
	return NewResultOutput(), nil
}

// AllowAllAuthnStrategy authenticates all requests
type AllowAllAuthnStrategy struct{}

// Authenticate all requests
func (s *AllowAllAuthnStrategy) Authenticate(r *AuthRequest) (Result, error) {
	return NewResultOutput(), nil
}
