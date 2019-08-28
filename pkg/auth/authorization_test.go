package auth

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const notInvitedIdentity = "decentraland:0x3e0857bbecd533d600dd17ab78e1ca5cf0749852/temp/03d757ee240348ec3d818d3f1d3f5902fcfecf3391fa6bc34a5c82863348db0581" //nolint
const validIdentity = "decentraland:0x3e0857bbecd533d600dd17ab78e1ca5cf0749858/temp/03d757ee240348ec3d818d3f1d3f5902fcfecf3391fa6bc34a5c82863348db0581"      //nolint

type authorizeRequestData struct {
	name            string
	requestHeaders  map[string]string
	resultAssertion func(t *testing.T, err error)
}

func assertError(t *testing.T, err error) {
	assert.NotNil(t, err)
}

func assertOkResult(t *testing.T, err error) {
	assert.Nil(t, err)
}

var authorizeRequestTc = []authorizeRequestData{ //nolint
	{
		name:            "Authorized AuthRequest",
		requestHeaders:  map[string]string{HeaderIdentity: validIdentity},
		resultAssertion: assertOkResult,
	},
	{
		name:            "Uninvited Address",
		requestHeaders:  map[string]string{HeaderIdentity: notInvitedIdentity},
		resultAssertion: assertError,
	},
	{
		name:            "Missing header",
		requestHeaders:  map[string]string{},
		resultAssertion: assertError,
	},
	{
		name:            "Invalid header",
		requestHeaders:  map[string]string{HeaderIdentity: "not an identity"},
		resultAssertion: assertError,
	},
}

func TestAuthorizeRequest(t *testing.T) {
	dcl := &inMemoryDcl{storage: initStorage()}
	inviteStrategy := &InviteStrategy{dcl: dcl}
	for _, tc := range authorizeRequestTc {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			req, err := buildRequest(tc.requestHeaders)
			if err != nil {
				t.Fail()
			}
			r, err := MakeFromHTTPRequest(req, "http://market.decentraland.org")
			if err != nil {
				t.Fail()
			}
			_, err = inviteStrategy.Authorize(r)
			tc.resultAssertion(t, err)
		})
	}
}

type inMemoryDcl struct {
	storage map[string]bool
}

func (dcl *inMemoryDcl) checkInvite(address string) (bool, error) {
	v, ok := dcl.storage[address]
	return ok && v, nil
}

func initStorage() map[string]bool {
	return map[string]bool{
		"0x3e0857bbecd533d600dd17ab78e1ca5cf0749858": true,
		"0x3e0857bbecd533d600dd17ab78e1ca5cf0749852": false}
}

func buildRequest(headers map[string]string) (*http.Request, error) {
	text := "{\"param1\":\"data1\",\"param2\":\"data2\"}"

	req, err := http.NewRequest(
		"POST", "http://market.decentraland.org/api/v1/marketplace", strings.NewReader(text))

	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req, err
}
