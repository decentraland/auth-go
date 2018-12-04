package authorization

import (
	"github.com/decentraland/auth-go/auth"
	"github.com/decentraland/auth-go/config"
	"github.com/decentraland/auth-go/utils"
)

type decentralandInvite struct {
	dcl decentraland
}

func NewStrategy(c *config.AuthConfig) auth.AuthorizationStrategy {
	return &decentralandInvite{dcl: newDclClient(c.DclApi)}
}

func (di *decentralandInvite) Authorize(r *auth.AuthRequest) (bool, error) {
	idHeader, err := utils.ExtractRequiredField(r.Credentials, "x-identity")
	if err != nil {
		return false, err
	}

	address, _, err := utils.ParseIdentity(idHeader)
	if err != nil {
		return false, err
	}

	invited, err := di.dcl.checkInvite(address)
	if err != nil {
		return false, err
	}

	return invited, nil
}
