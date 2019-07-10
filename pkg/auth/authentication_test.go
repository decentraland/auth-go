package auth

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/decentraland/auth-go/pkg/ephemeral"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

const wrongSignature = "1c9d60a1883ecad4935ef8fabeaba74c0841f8aa0d981247fc25c92611ac645f2bf1b181406dde06993ed3f57f2d935e1a0ac95a68ec546f8d30e9b2e616dd97"
const expiredCertificate = "0x446563656e7472616c616e64204163636573732041757468204b65793a203034333333323766373364306633663837313731393039393535643837613162393339333736333430366266356438663139343032353665653064363265623561336139633332303638366262653266656637383366666537356239653635623735616232653161616134383431663134656637653866613663666136663035356120546f6b656e3a206d61696e6e65743a2f2f3078313233343520446174653a20323031302d31312d32395431353a33373a30325a20457870697265733a20323031302d31312d32395431353a34373a30325a"

type validateCredentialsData struct {
	name            string
	tolerance       int64
	errorMessage    string
	modifiedHeaders map[string]string
	resultAssertion func(t *testing.T, err error, expectedMsg string)
}

func assertErrorMessage(t *testing.T, err error, expectedMsg string) {
	assert.NotNil(t, err)
	assert.Equal(t, expectedMsg, err.Error(), fmt.Sprintf("Expected Message: '%s'. Got: '%s'", expectedMsg, err.Error()))
}

func assertResultOk(t *testing.T, err error, _ string) {
	if err != nil {
		t.Fail()
	}
}

var validateCredentialsTc = []validateCredentialsData{
	{
		name:            "Valid Credentials",
		tolerance:       1000,
		resultAssertion: assertResultOk,
	},
	{
		name:            "Expired AuthRequest",
		tolerance:       -1,
		errorMessage:    "request expired",
		resultAssertion: assertErrorMessage,
	},
	{
		name:      "Invalid Timestamp",
		tolerance: 10000,
		modifiedHeaders: map[string]string{
			HeaderTimestamp: "This is not a timestamp"},
		errorMessage:    "invalid timestamp",
		resultAssertion: assertErrorMessage,
	},
	{
		name:      "Invalid identity header",
		tolerance: 1000,
		modifiedHeaders: map[string]string{
			HeaderIdentity: "not the identity header"},
		errorMessage:    "malformed 'x-identity' header: not the identity header",
		resultAssertion: assertErrorMessage,
	},
	{
		name:      "Invalid Signature",
		tolerance: 1000,
		modifiedHeaders: map[string]string{
			HeaderSignature: wrongSignature,
		},
		errorMessage:    "invalid Signature",
		resultAssertion: assertErrorMessage,
	},
	{
		name:      "Invalid Certificate Signature",
		tolerance: 1000,
		modifiedHeaders: map[string]string{
			HeaderCertSignature: "0x884e",
		},
		errorMessage:    "invalid certificate signature",
		resultAssertion: assertErrorMessage,
	},
	{
		name:      "Invalid Certificate",
		tolerance: 0,
		modifiedHeaders: map[string]string{
			HeaderCert: "0x4465",
		},
		errorMessage:    "invalid certificate",
		resultAssertion: assertErrorMessage,
	},
	{
		name:      "Expired Certificate",
		tolerance: 1000,
		modifiedHeaders: map[string]string{
			HeaderCert: expiredCertificate,
		},
		errorMessage:    "expired certificate",
		resultAssertion: assertErrorMessage,
	},
	{
		name:      "Wrong Certificate type",
		tolerance: 1000,
		modifiedHeaders: map[string]string{
			HeaderAuthType: "third-party"},
		errorMessage:    "invalid credential type",
		resultAssertion: assertErrorMessage,
	},
	{
		name:      "Fail request way into future",
		tolerance: 1000,
		modifiedHeaders: map[string]string{
			HeaderTimestamp: strconv.FormatInt(time.Now().Unix()+1500, 10)},
		errorMessage:    "request expired",
		resultAssertion: assertErrorMessage,
	},
}

func TestValidateCredentials(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	accountInfo := &ephemeral.EthAccountInfo{TokenAddress: "0x12345", Account: getEthAddress(key), Passphrase: ""}

	mock := &ethClientMock{network: "1", key: key}

	for _, tc := range validateCredentialsTc {
		t.Run(tc.name, func(t *testing.T) {

			ephKey, err := ephemeral.GenerateEthEphemeralKey(accountInfo, mock, 1000)
			require.NoError(t, err)

			v := &SelfGrantedStrategy{RequestTolerance: tc.tolerance}

			req, err := buildAuthRequest()
			err = ephKey.AddRequestHeaders(req)
			require.NoError(t, err)

			if tc.modifiedHeaders != nil {
				for header, val := range tc.modifiedHeaders {
					req.Header.Set(header, val)
				}
			}

			r, err := MakeFromHttpRequest(req, "http://market.decentraland.org")
			if err != nil {
				t.Fail()
			}
			_, err = v.Authenticate(r)
			tc.resultAssertion(t, err, tc.errorMessage)
		})
	}
}

func TestCheckRequestTimestamp(t *testing.T) {
	var tolerance = int64(1000)

	// Within tolerance in the past
	err := checkRequestExpiration(strconv.Itoa(int(time.Now().Unix()-999)), tolerance)
	require.NoError(t, err)

	// Within tolerance in the future
	err = checkRequestExpiration(strconv.Itoa(int(time.Now().Unix()+999)), tolerance)
	require.NoError(t, err)

	// Outside tolerance in the future
	err = checkRequestExpiration(strconv.Itoa(int(time.Now().Unix()+1001)), tolerance)
	require.Error(t, err)

	// Outside tolerance in the past
	err = checkRequestExpiration(strconv.Itoa(int(time.Now().Unix()-1001)), tolerance)
	require.Error(t, err)
}

func buildAuthRequest() (*http.Request, error) {
	text := "{\"param1\":\"data1\",\"param2\":\"data2\"}"

	return http.NewRequest("POST", "http://market.decentraland.org/api/v1/marketplace", strings.NewReader(text))
}

type ethClientMock struct {
	network string
	key     *ecdsa.PrivateKey
}

func (c *ethClientMock) NetVersion() (string, error) {
	return c.network, nil
}

func (c *ethClientMock) ListAccounts() ([]string, error) {
	return nil, nil
}

func (c *ethClientMock) Sign(message string, address string, pass string) (string, error) {
	decodedMsg, err := hexutil.Decode(message)
	if err != nil {
		return "", err
	}
	mBytes, _ := core.SignHash(decodedMsg)
	sigBytes, err := crypto.Sign(mBytes, c.key)
	if err != nil {
		return "", err
	}
	return hexutil.Encode(sigBytes), nil
}

func (c *ethClientMock) GetDefaultAccount() (string, error) {
	return "", nil
}

func getEthAddress(key *ecdsa.PrivateKey) string {
	return crypto.PubkeyToAddress(key.PublicKey).Hex()
}
