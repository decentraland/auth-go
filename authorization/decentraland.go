package authorization

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
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
	dclApi string
}

func newDclClient(dclApi string) *dclClient {
	return &dclClient{dclApi: dclApi}
}

func (dcl *dclClient) checkInvite(address string) (bool, error) {
	var resp validationResponse
	err := doGet(buildUrl(dcl.dclApi, "/invites/%s/validate", address), &resp)
	if err != nil {
		return false, err
	}
	return resp.Data.Invited, nil
}

func buildUrl(basePath string, relPath string, args ...interface{}) string {
	u, _ := url.Parse(basePath)
	u.Path = path.Join(u.Path, fmt.Sprintf(relPath, args...))
	url, _ := url.PathUnescape(u.String())
	return url
}

func doGet(url string, response interface{}) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	return json.NewDecoder(resp.Body).Decode(response)
}
