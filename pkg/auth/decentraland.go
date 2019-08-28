package auth

import (
	"encoding/json"
	"net/http"
)

type decentraland interface {
	checkInvite(address string) (bool, error)
}

type validationResponse struct {
	Ok   bool `json:"ok"`
	Data data `json:"data"`
}

type data struct {
	Address string `json:"address"`
	Invited bool   `json:"invited"`
}

type dclClient struct {
	dclAPI string
}

func newDclClient(dclAPI string) *dclClient {
	return &dclClient{dclAPI: dclAPI}
}

func (dcl *dclClient) checkInvite(address string) (bool, error) {
	var resp validationResponse
	err := doGet(buildURL(dcl.dclAPI, "/invites/%s/validate", address), &resp)
	if err != nil {
		return false, err
	}
	return resp.Data.Invited, nil
}

func doGet(url string, response interface{}) error {
	resp, err := http.Get(url) //nolint
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint
	return json.NewDecoder(resp.Body).Decode(response)
}
