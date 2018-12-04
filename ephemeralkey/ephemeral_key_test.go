package ephemeralkey

import (
	"bytes"
	"encoding/hex"
	"github.com/ethereum/go-ethereum/crypto"
	"regexp"
	"testing"
	"time"

	"github.com/decentraland/auth-go/mocks"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

const expectedSignature = "0x2de0bfbf063cd4c9f4565fc68bb6acadf9d06e278bfd876eefb31e62a9071adc17dab32a3bd4695bb8319e99319a3a26d366880d03b5db0a43ff584f6ee27ac81b"
const testAddress = "0x4256ab370067377cf2c82f3379c98a3817a0c6d7"
const ttlInMinutes = 10

func TestGenerateEphemeralKeys(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	mockEth := mocks.NewMockEthClient(mockController)

	mockEth.EXPECT().NetVersion().Return("1", nil).Times(1)
	mockEth.EXPECT().ListAccounts().Return([]string{testAddress}, nil).Times(1)
	//The message to sign will change each time
	mockEth.EXPECT().Sign(gomock.Any(), testAddress, "").Return(expectedSignature, nil).Times(1)

	duration := time.Minute * time.Duration(ttlInMinutes)
	var g = &EphemeralKeysGenerator{ethClient: mockEth, timeToLive: duration}

	acc, err := g.GetDefaultAccount()

	if err != nil {
		t.Fail()
	}

	credential, err := g.GenerateEphemeralKeys("0x12345", acc, "")

	assert.Nil(t, err)
	assert.NotNil(t, credential)

	assert.Equal(t, testAddress, credential.Address)
	assert.Equal(t, expectedSignature, credential.Signature)

	assertExpirationTime(t, credential, duration)
}

func TestGenerateDifferentKeys(t *testing.T) {
	mockController := gomock.NewController(t)
	defer mockController.Finish()
	mockEth := mocks.NewMockEthClient(mockController)

	mockEth.EXPECT().NetVersion().Return("1", nil).AnyTimes()
	mockEth.EXPECT().ListAccounts().Return([]string{testAddress}, nil).AnyTimes()
	//The message to sign will change each time
	mockEth.EXPECT().Sign(gomock.Any(), testAddress, "").Return(expectedSignature, nil).AnyTimes()

	duration := time.Minute * time.Duration(ttlInMinutes)
	var g = &EphemeralKeysGenerator{ethClient: mockEth, timeToLive: duration}

	acc, err := g.GetDefaultAccount()

	if err != nil {
		t.Fail()
	}

	c1, err := g.GenerateEphemeralKeys("0x12345", acc, "")
	c2, err := g.GenerateEphemeralKeys("0x12345", acc, "")

	assert.False(t, bytes.Equal(crypto.FromECDSA(c1.EphemeralPrivateKey), crypto.FromECDSA(c2.EphemeralPrivateKey)))
}

func assertExpirationTime(t *testing.T, c *Credentials, duration time.Duration) {
	bs, err := hex.DecodeString(c.Message[2:])
	if err != nil {
		t.Errorf(err.Error())
	}
	msg := string(bs)

	datesRegex := *regexp.MustCompile(".*Date: (.*) Expires: (.*)")
	if !datesRegex.MatchString(msg) {
		t.Error()
	}

	dates := datesRegex.FindAllStringSubmatch(msg, -1)

	credentialDate, err := time.Parse(time.RFC3339, dates[0][1])
	if err != nil {
		t.Fail()
	}
	expirationDate, err := time.Parse(time.RFC3339, dates[0][2])
	if err != nil {
		t.Fail()
	}

	assert.Equal(t, duration, expirationDate.Sub(credentialDate))
}