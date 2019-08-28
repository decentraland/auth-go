package auth

import (
	"fmt"

	"github.com/decentraland/auth-go/internal/utils"
)

const authzIdentityPattern = "decentraland:(.*)\\/temp\\/(.*)"

// InviteStrategy authorize requests if the eth address was invited
type InviteStrategy struct {
	dcl decentraland
}

// NewInviteStrategy retrieves a new Authorization strategy
func NewInviteStrategy(dclAPI string) *InviteStrategy {
	d := newDclClient(dclAPI)
	return &InviteStrategy{dcl: d}
}

// Authorize checks if the eth address was invited
func (di *InviteStrategy) Authorize(r *AuthRequest) (Result, error) {
	output := NewResultOutput()
	requiredCredentials := []string{HeaderIdentity}
	if err := utils.ValidateRequiredCredentials(r.Credentials, requiredCredentials); err != nil {
		return output, err
	}

	tokens, err := utils.ParseTokensWithRegex(r.Credentials[HeaderIdentity], authzIdentityPattern)
	if err != nil {
		return output, err
	}

	if len(tokens) != 2 {
		return output, MissingCredentialsError{"unable to exctract required information from 'x-identity' header"}
	}

	address := tokens[0]

	invited, err := di.dcl.checkInvite(address)
	if err != nil {
		return output, err
	}

	if !invited {
		return output, AuthorizationError{fmt.Sprintf("unauthorzed address: %s", address)}
	}
	return output, nil
}

// AllowAllAuthzStrategy  authorize all requests
type AllowAllAuthzStrategy struct{}

// Authorize all requests
func (di *AllowAllAuthzStrategy) Authorize(r *AuthRequest) (Result, error) {
	return NewResultOutput(), nil
}
