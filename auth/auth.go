package auth

import (
	"crypto/sha256"
	"github.com/decentraland/auth-go/utils"
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

func NewAuthProvider(authn AuthenticationStrategy, authz AuthorizationStrategy) AuthProvider {
	return &authProviderImpl{
		authn: authn,
		authz: authz,
	}
}

// Authenticate and Authorize request based on the AuthorizationStrategy
func (ah *authProviderImpl) ApproveRequest(r *AuthRequest) (bool, error) {
	auth, err := ah.authn.Authenticate(r)
	if err != nil {
		return false, &AuthenticationError{err.Error()}
	}

	if !auth {
		return auth, nil
	}

	aut, err := ah.authz.Authorize(r)
	if err != nil {
		return false, &AuthorizationError{err.Error()}
	}
	return aut, nil
}

type AuthenticationError struct {
	cause string
}
type AuthorizationError struct {
	cause string
}

func (e *AuthenticationError) Error() string {
	return e.cause
}

func (e *AuthorizationError) Error() string {
	return e.cause
}

// Retrieves a SHA256 checksum of teh request content
func (r *AuthRequest) Hash() ([]byte, error) {
	method := r.Method
	url := r.URL
	timestamp, err := utils.ExtractRequiredField(r.Credentials, "x-timestamp")
	if err != nil {
		return nil, err
	}
	toSign := []byte(method)
	toSign = append(toSign, []byte(url)...)
	toSign = append(toSign, []byte(timestamp)...)
	if r.Content != nil {
		toSign = append(toSign, r.Content...)
	}
	result := sha256.Sum256(toSign)
	return result[:], nil
}
