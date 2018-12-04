package ephemeralkey

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"time"

	"encoding/hex"
	"github.com/decentraland/authentication-go/ethereum"
)

// Credentials
type Credentials struct {
	EphemeralPrivateKey *ecdsa.PrivateKey
	Address             string
	Signature           string
	Message             string
	ExpirationTime      string
}

// EphemeralKeysGenerator
type EphemeralKeysGenerator struct {
	ethClient  ethereum.EthClient
	timeToLive time.Duration
}

// NewEphemeralKeysGenerator Retrieves a new instace of the key generator
func NewEphemeralKeysGenerator(ethNodeLocation string, keysTimeToLive int) (*EphemeralKeysGenerator, error) {
	c, err := ethereum.NewEthClient(ethNodeLocation)
	if err != nil {
		return nil, err
	}
	return &EphemeralKeysGenerator{
		timeToLive: time.Minute * time.Duration(keysTimeToLive),
		ethClient:  c,
	}, nil
}

// GenerateEphemeralKeys generates an ephemeral key using the account in the configured node
// The 'personal' rpc module need to me enable on the external node
func (g *EphemeralKeysGenerator) GenerateEphemeralKeys(tokenAddress string, account string, passphrase string) (*Credentials, error) {
	pvKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	net, err := getNetwork(g.ethClient)
	if err != nil {
		return nil, err
	}
	date := time.Now().UTC()
	expTime := g.getExpirationDateString(date)

	message := hexutil.Encode([]byte(buildMessage(pvKey.PublicKey, tokenAddress, net, date, expTime)))

	signature, err := g.ethClient.Sign(message, account, passphrase)
	if err != nil {
		return nil, err
	}

	return &Credentials{
		EphemeralPrivateKey: pvKey,
		ExpirationTime:      formatCredentialDate(expTime),
		Address:             account,
		Message:             message,
		Signature:           signature,
	}, nil
}

// GetDefaultAccount gets the default account (first on the list) to generate the Ephemeral keys
func (g *EphemeralKeysGenerator) GetDefaultAccount() (string, error) {
	accounts, err := g.ethClient.ListAccounts()
	if err != nil {
		return "", err
	}
	if len(accounts) < 1 {
		return "", errors.New("No Account found")
	}
	return accounts[0], nil
}

// Calculates the expiration date in UTC an retrieves it as a ISO string
func (g *EphemeralKeysGenerator) getExpirationDateString(date time.Time) time.Time {
	return date.Add(g.timeToLive).UTC()
}

// Retrieves the message to sign
func buildMessage(key ecdsa.PublicKey, tokenAddress string, n string, date time.Time, expiration time.Time) string {
	ks := hex.EncodeToString(crypto.FromECDSAPub(&key))
	fmtDate := formatCredentialDate(date)
	fmtExp := formatCredentialDate(expiration)
	return fmt.Sprintf("Decentraland Access Auth Key: %s Token: %s://%s Date: %s Expires: %s", ks, n, tokenAddress, fmtDate, fmtExp)
}

func getNetwork(c ethereum.EthClient) (string, error) {
	id, err := c.NetVersion()
	if err != nil {
		return "", err
	}
	return getNetworkNameByID(id), nil
}

func formatCredentialDate(date time.Time) string {
	return date.Format(time.RFC3339)
}

func getNetworkNameByID(id string) string {
	switch id {
	case "1":
		return "mainnet"
	case "2":
		return "morden"
	case "3":
		return "ropsten"
	case "4":
		return "rinkeby"
	case "42":
		return "kovan"
	default:
		return "unknown"
	}
}
