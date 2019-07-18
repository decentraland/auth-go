package auth

import (
	"fmt"
	"github.com/decentraland/auth-go/internal/utils"
)

const authzIdentityPattern = "decentraland:(.*)\\/temp\\/(.*)"

type InviteStrategy struct {
	dcl decentraland
}

func NewInviteStrategy(dclApi string) *InviteStrategy {
	d := newDclClient(dclApi)
	return &InviteStrategy{dcl: d}
}

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
		return output, fmt.Errorf("unable to exctract required information from 'x-identity' header")
	}

	address := tokens[0]

	invited, err := di.dcl.checkInvite(address)
	if err != nil {
		return output, err
	}

	if !invited {
		return output, fmt.Errorf("unauthorzed address: %s", address)
	}
	return output, nil
}

// Authorize all requests
type AllowAllAuthzStrategy struct{}

func (di *AllowAllAuthzStrategy) Authorize(r *AuthRequest) (Result, error) {
	return NewResultOutput(), nil
}
