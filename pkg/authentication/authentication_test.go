package authentication

import (
	"fmt"
	"github.com/decentraland/auth-go/pkg/auth"
	"github.com/stretchr/testify/assert"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

const validCertificate = "0x446563656e7472616c616e64204163636573732041757468204b65793a203034613939623066383966306234623935366164666261343733366666663639336361353935663662636233386438623939636564633162633833356432333234356364336632383562373163623232633336373233616638666139613261333439636235613962666464376339623765643030363633666330323462613031343720546f6b656e3a206d61696e6e65743a2f2f3078313233343520446174653a20323031392d30322d31335431383a31353a35325a20457870697265733a20323230392d30342d30335430343a35353a35325a"
const validCertificateSignature = "0x0df9472bd84af4fd1ef0428ebc60f4fc46a41f07574f266c3b35439dcb3dd6430dfc61ae4d591d0fb8e8e9a719802aa62a15a7505a392e3448c03bc3be3b3deb1b"
const validIdentity = "decentraland:0x3e0857bbecd533d600dd17ab78e1ca5cf0749858/temp/0x03a99b0f89f0b4b956adfba4736fff693ca595f6bcb38d8b99cedc1bc835d23245"
const validSignature = "b640b616fabd440cd9632f8fab5fe1f5c18d4c8304017ea8b70b0790b2a215f709c2f10ede5da85381c7b24680ad5e90be961929df9c686ee315cf68d4bff346"
const validTimeStamp = "1550080457"

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
	seconds, _ := strconv.ParseInt(timestamp, 10, 64)
	current := time.Now().Unix()
	return (current - seconds) + 1000
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
			"x-timestamp":             validTimeStamp,
			"x-auth-type":             "self-granted"},
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
			"x-timestamp":             validTimeStamp,
			"x-auth-type":             "self-granted"},
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
			"x-timestamp":             "This is not a timestamp",
			"x-auth-type":             "self-granted"},
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
			"x-timestamp":             validTimeStamp,
			"x-auth-type":             "self-granted"},
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
			"x-timestamp":             validTimeStamp,
			"x-auth-type":             "self-granted"},
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
			"x-timestamp":             validTimeStamp,
			"x-auth-type":             "self-granted"},
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
			"x-timestamp":             validTimeStamp,
			"x-auth-type":             "self-granted"},
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
			"x-timestamp":             validTimeStamp,
			"x-auth-type":             "self-granted"},
		errorMessage:    "expired certificate",
		resultAssertion: assertErrorMessage,
	},
	{
		name:          "Wrong Certificate type",
		timeToLiveGen: generateValidTTL,
		requestHeaders: map[string]string{
			"x-certificate":           validCertificate,
			"x-certificate-signature": validCertificateSignature,
			"x-identity":              validIdentity,
			"x-signature":             validSignature,
			"x-timestamp":             validTimeStamp,
			"x-auth-type":             "third-party"},
		errorMessage:    "invalid credential type",
		resultAssertion: assertErrorMessage,
	},
}

func TestValidateCredentials(t *testing.T) {
	for _, tc := range validateCredentialsTc {
		t.Run(tc.name, func(t *testing.T) {
			v := &SelfGrantedStrategy{RequestLifeSpan: tc.timeToLiveGen(tc.requestHeaders["x-timestamp"])}
			req, err := buildRequest(tc.requestHeaders)
			if err != nil {
				t.Fail()
			}
			r, err := auth.MakeFromHttpRequest(req)
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
