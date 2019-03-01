package authorization

import (
	"fmt"
	"github.com/decentraland/auth-go/internal/utils"
	"github.com/decentraland/auth-go/pkg/auth"
)

const identityPattern = "decentraland:(.*)\\/temp\\/(.*)"

type InviteStrategy struct {
	dcl decentraland
}

func NewInviteStrategy(dclApi string) *InviteStrategy {
	d := newDclClient(dclApi)
	return &InviteStrategy{dcl: d}
}

func (di *InviteStrategy) Authorize(r *auth.AuthRequest) (bool, error) {
	requiredCredentials := []string{"x-identity"}
	if err := utils.ValidateRequiredCredentials(r.Credentials, requiredCredentials); err != nil {
		return false, err
	}

	tokens, err := utils.ParseTokensWithRegex(r.Credentials["x-identity"], identityPattern)
	if err != nil {
		return false, err
	}

	if len(tokens) != 2 {
		return false, fmt.Errorf("unable to exctract required information from 'x-identity' header")
	}

	address := tokens[0]

	invited, err := di.dcl.checkInvite(address)
	if err != nil {
		return false, err
	}

	return invited, nil
}

// Authorize all requests
type AllowAllStrategy struct{}

func (di *AllowAllStrategy) Authorize(r *auth.AuthRequest) (bool, error) {
	return true, nil
}
