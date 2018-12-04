package authentication

import (
	"fmt"
	"github.com/decentraland/auth-go/config"
	http2 "github.com/decentraland/auth-go/http"
	"github.com/decentraland/auth-go/utils"
	"github.com/stretchr/testify/assert"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

const validCertificate = "0x446563656e7472616c616e642041636365737320417574680a4b65793a203033643735376565323430333438656333643831386433663164336635393032666366656366333339316661366263333461356338323836333334386462303538312e0a546f6b656e3a206d61696e6e65743a2f2f307831323334350a446174653a20323031382d31312d32375432303a30303a35392e3635365a0a457870697265733a20323031382d31322d32375432303a30303a35392e3635365a"
const validCertificateSignature = "0x884e2bddc6c67c6c1214a29281d52866c974339c1758f91f390ab562867ee7743ca45121c8fdc35932eba1221f9b376886976a7fbd50fe9b1514d5d1d7aec92c1b"
const validIdentity = "decentraland:0x3e0857bbecd533d600dd17ab78e1ca5cf0749858/temp/03d757ee240348ec3d818d3f1d3f5902fcfecf3391fa6bc34a5c82863348db0581"
const validSignature = "414df50b55d93ced6b227999f0e4d2167f515cab9dba775e9067f093522c43db7436abe82286181555441a88c46b4fb2f3dd48860cdfe4408c86aaeff68759b7"
const validTimeStamp = "1543348857349"

const wrongSignature = "1c9d60a1883ecad4935ef8fabeaba74c0841f8aa0d981247fc25c92611ac645f2bf1b181406dde06993ed3f57f2d935e1a0ac95a68ec546f8d30e9b2e616dd97"
const expiredCertificate = "0x446563656e7472616c616e64204163636573732041757468204b65793a203034333333323766373364306633663837313731393039393535643837613162393339333736333430366266356438663139343032353665653064363265623561336139633332303638366262653266656637383366666537356239653635623735616232653161616134383431663134656637653866613663666136663035356120546f6b656e3a206d61696e6e65743a2f2f3078313233343520446174653a20323031302d31312d32395431353a33373a30325a20457870697265733a20323031302d31312d32395431353a34373a30325a"

type validateCredentialsData struct {
	name            string
	timeToLiveGen   func(timestamp string) int64
	requestHeaders  map[string]string
	errorMessage    string
	resultAssertion func(t *testing.T, err error, expectedMsg string)
}

func assertErrorMessage(t *testing.T, err error, expectedMsg string) {
	assert.NotNil(t, err)
	assert.Equal(t, expectedMsg, err.Error(), fmt.Sprintf("Expected Message: '%s'. Got: '%s'", expectedMsg, err.Error()))
}

func assertResultOk(t *testing.T, err error, expectedMsg string) {
	if err != nil {
		t.Fail()
	}
}

func generateValidTTL(timestamp string) int64 {
	milliseconds, _ := strconv.ParseInt(timestamp, 10, 64)
	current := utils.GetCurrentTimestamp()
	return (current - milliseconds) + 1000
}

var validateCredentialsTc = []validateCredentialsData{
	{
		name:          "Valid Credentials",
		timeToLiveGen: generateValidTTL,
		requestHeaders: map[string]string{
			"x-certificate":           validCertificate,
			"x-certificate-signature": validCertificateSignature,
			"x-identity":              validIdentity,
			"x-signature":             validSignature,
			"x-timestamp":             validTimeStamp},
		resultAssertion: assertResultOk,
	},
	{
		name: "Expired AuthRequest",
		timeToLiveGen: func(timestamp string) int64 {
			return 0
		},
		requestHeaders: map[string]string{
			"x-certificate":           validCertificate,
			"x-certificate-signature": validCertificateSignature,
			"x-identity":              validIdentity,
			"x-signature":             validSignature,
			"x-timestamp":             validTimeStamp},
		errorMessage:    "request expired",
		resultAssertion: assertErrorMessage,
	},
	{
		name: "Invalid Timestamp",
		timeToLiveGen: func(timestamp string) int64 {
			return 10000
		},
		requestHeaders: map[string]string{
			"x-certificate":           validCertificate,
			"x-certificate-signature": validCertificateSignature,
			"x-identity":              validIdentity,
			"x-signature":             validSignature,
			"x-timestamp":             "This is not a timestamp"},
		errorMessage:    "invalid timestamp",
		resultAssertion: assertErrorMessage,
	},
	{
		name:          "Invalid identity header",
		timeToLiveGen: generateValidTTL,
		requestHeaders: map[string]string{
			"x-certificate":           validCertificate,
			"x-certificate-signature": validCertificateSignature,
			"x-identity":              "not the identity header",
			"x-signature":             validSignature,
			"x-timestamp":             validTimeStamp},
		errorMessage:    "malformed 'x-identity' header: not the identity header",
		resultAssertion: assertErrorMessage,
	},
	{
		name:          "Invalid Signature",
		timeToLiveGen: generateValidTTL,
		requestHeaders: map[string]string{
			"x-certificate":           validCertificate,
			"x-certificate-signature": validCertificateSignature,
			"x-identity":              validIdentity,
			"x-signature":             wrongSignature,
			"x-timestamp":             validTimeStamp},
		errorMessage:    "invalid Signature",
		resultAssertion: assertErrorMessage,
	},
	{
		name:          "Invalid Certificate Signature",
		timeToLiveGen: generateValidTTL,
		requestHeaders: map[string]string{
			"x-certificate":           validCertificate,
			"x-certificate-signature": "0x884e",
			"x-identity":              validIdentity,
			"x-signature":             validSignature,
			"x-timestamp":             validTimeStamp},
		errorMessage:    "invalid certificate signature",
		resultAssertion: assertErrorMessage,
	},
	{
		name:          "Invalid Certificate",
		timeToLiveGen: generateValidTTL,
		requestHeaders: map[string]string{
			"x-certificate":           "0x4465",
			"x-certificate-signature": validCertificateSignature,
			"x-identity":              validIdentity,
			"x-signature":             validSignature,
			"x-timestamp":             validTimeStamp},
		errorMessage:    "invalid certificate",
		resultAssertion: assertErrorMessage,
	},
	{
		name:          "Expired Certificate",
		timeToLiveGen: generateValidTTL,
		requestHeaders: map[string]string{
			"x-certificate":           expiredCertificate,
			"x-certificate-signature": validCertificateSignature,
			"x-identity":              validIdentity,
			"x-signature":             validSignature,
			"x-timestamp":             validTimeStamp},
		errorMessage:    "expired certificate",
		resultAssertion: assertErrorMessage,
	},
}

func TestValidateCredentials(t *testing.T) {
	for _, tc := range validateCredentialsTc {
		t.Run(tc.name, func(t *testing.T) {
			c := &config.AuthConfig{DclApi: "", RequestAllowedTTL: tc.timeToLiveGen(tc.requestHeaders["x-timestamp"]), RequestMaxSize: 100000}
			v := NewStrategy(c)
			req, err := buildRequest(tc.requestHeaders)
			if err != nil {
				t.Fail()
			}
			r, err := http2.TransformHttpRequest(req)
			if err != nil {
				t.Fail()
			}
			_, err = v.Authenticate(r)
			tc.resultAssertion(t, err, tc.errorMessage)
		})
	}
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
