package authorization

import (
	http2 "github.com/decentraland/authentication-go/http"
	"github.com/stretchr/testify/assert"
	"net/http"
	"strings"
	"testing"
)

const notInvitedIdentity = "decentraland:0x3e0857bbecd533d600dd17ab78e1ca5cf0749852/temp/03d757ee240348ec3d818d3f1d3f5902fcfecf3391fa6bc34a5c82863348db0581"
const validIdentity = "decentraland:0x3e0857bbecd533d600dd17ab78e1ca5cf0749858/temp/03d757ee240348ec3d818d3f1d3f5902fcfecf3391fa6bc34a5c82863348db0581"

type authorizeRequestData struct {
	name            string
	requestHeaders  map[string]string
	resultAssertion func(t *testing.T, result bool, err error)
}

func assertError(t *testing.T, result bool, err error) {
	assert.False(t, result)
	assert.NotNil(t, err)
}

func assertTrueResult(t *testing.T, result bool, err error) {
	assert.True(t, result)
	assert.Nil(t, err)
}

func assertFalseResult(t *testing.T, result bool, err error) {
	assert.False(t, result)
	assert.Nil(t, err)
}

var authorizeRequestTc = []authorizeRequestData{
	{
		name:            "Authorized AuthRequest",
		requestHeaders:  map[string]string{"x-identity": validIdentity},
		resultAssertion: assertTrueResult,
	},
	{
		name:            "Uninvited Address",
		requestHeaders:  map[string]string{"x-identity": notInvitedIdentity},
		resultAssertion: assertFalseResult,
	},
	{
		name:            "Missing header",
		requestHeaders:  map[string]string{},
		resultAssertion: assertError,
	},
	{
		name:            "Invalid header",
		requestHeaders:  map[string]string{"x-identity": "not an identity"},
		resultAssertion: assertError,
	},
}

func TestAuthorizeRequest(t *testing.T) {
	dcl := &inMemoryDcl{storage: initStorage()}
	inviteStrategy := &decentralandInvite{dcl: dcl}
	for _, tc := range authorizeRequestTc {
		t.Run(tc.name, func(t *testing.T) {
			req, err := buildRequest(tc.requestHeaders)
			if err != nil {
				t.Fail()
			}
			r, err := http2.TransformHttpRequest(req)
			if err != nil {
				t.Fail()
			}
			result, err := inviteStrategy.Authorize(r)
			tc.resultAssertion(t, result, err)
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

	req, err := http.NewRequest("POST", "http://market.decentraland.org/api/v1/marketplace", strings.NewReader(text))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req, err
}
