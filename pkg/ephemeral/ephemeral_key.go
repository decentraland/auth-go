package ephemeral

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/decentraland/auth-go/pkg/commons"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"net/http"
	"strconv"
	"time"

	"encoding/hex"
	"github.com/decentraland/auth-go/internal/ethereum"
)

// EthEphemeralKey Uses the blockchain information to generate the key certificate
type EthEphemeralKey struct {
	EphemeralPrivateKey *ecdsa.PrivateKey
	Address             string
	Signature           string
	Message             string
	ExpirationTime      time.Time
}

// Ethereum account information
type EthAccountInfo struct {
	TokenAddress string
	Account      string
	Passphrase   string
}

// GenerateCredential generates an ephemeral key using the account in the configured node
// The 'personal' rpc module need to me enable on the external node
func GenerateEthEphemeralKey(account *EthAccountInfo, ethClient ethereum.EthClient, keysTimeToLive int) (*EthEphemeralKey, error) {
	pvKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	net, err := getNetwork(ethClient)
	if err != nil {
		return nil, err
	}

	ttl := time.Minute * time.Duration(keysTimeToLive)
	date := time.Now().UTC()
	expTime := getExpirationTime(ttl, date)

	message := hexutil.Encode([]byte(buildMessage(pvKey.PublicKey, account.TokenAddress, net, date, expTime)))

	signature, err := ethClient.Sign(message, account.Account, account.Passphrase)
	if err != nil {
		return nil, err
	}

	return &EthEphemeralKey{
		EphemeralPrivateKey: pvKey,
		ExpirationTime:      expTime,
		Address:             account.Account,
		Message:             message,
		Signature:           signature,
	}, nil
}

// Calculates the expiration date in UTC an retrieves it as a ISO string
func getExpirationTime(ttl time.Duration, date time.Time) time.Time {
	return date.Add(ttl).UTC()
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

// Adds all  needed credentials to authenticate the credential owner as request headers
func (c *EthEphemeralKey) AddRequestHeaders(r *http.Request) error {
	timestamp := time.Now().Unix()

	msg, err := commons.GenerateHttpRequestHash(r, timestamp)
	if err != nil {
		return err
	}

	fieldExtractor := func() (map[string]string, error) {
		return c.generateCredentials(msg, timestamp)
	}

	return completeRequest(r, fieldExtractor)
}

// Generates all the needed credentials to authenticate the credential owner
func (c *EthEphemeralKey) MakeCredentials(msg []byte) (map[string]string, error) {
	timestamp := time.Now().Unix()

	msgHash, err := commons.GenerateMessageHash(msg, timestamp)
	if err != nil {
		return nil, err
	}
	return c.generateCredentials(msgHash, timestamp)
}

func (c *EthEphemeralKey) generateCredentials(msg []byte, timestamp int64) (map[string]string, error) {
	signature, err := commons.SignMessage(msg, c.EphemeralPrivateKey)
	if err != nil {
		return nil, err
	}

	fields := map[string]string{}

	fields["x-signature"] = hex.EncodeToString(signature)
	fields["x-identity"] = fmt.Sprintf("decentraland:%s/temp/%s", c.Address, hexutil.Encode(crypto.CompressPubkey(&c.EphemeralPrivateKey.PublicKey)))
	fields["x-certificate"] = c.Message
	fields["x-certificate-signature"] = c.Signature
	fields["x-timestamp"] = strconv.FormatInt(timestamp, 10)
	fields["x-auth-type"] = "self-granted"

	return fields, nil
}

type EphemeralKey struct {
	PrivateKey *ecdsa.PrivateKey
}

type EphemeralKeyConfig struct {
	PrivateKey *ecdsa.PrivateKey
}

// Generate a EphemeralKey which is basically a ecdsa key
func NewEphemeralKey(config *EphemeralKeyConfig) (*EphemeralKey, error) {
	eph := &EphemeralKey{PrivateKey: config.PrivateKey}

	if eph.PrivateKey == nil {
		pvKey, err := crypto.GenerateKey()
		eph.PrivateKey = pvKey
		if err != nil {
			return nil, err
		}
	}

	return eph, nil
}

func (c *EphemeralKey) PublicKey() *ecdsa.PublicKey {
	return &c.PrivateKey.PublicKey
}

// Adds all  needed credentials to authenticate the credential owner as request headers
func (c *EphemeralKey) AddRequestHeaders(r *http.Request, accessToken string) error {
	timestamp := time.Now().Unix()

	msg, err := commons.GenerateHttpRequestHash(r, timestamp)
	if err != nil {
		return err
	}

	fieldExtractor := func() (strings map[string]string, e error) {
		return c.generateCredentials(msg, accessToken, timestamp)
	}

	return completeRequest(r, fieldExtractor)
}

// Generates all the needed credentials to authenticate the credential owner
func (c *EphemeralKey) MakeCredentials(message []byte, accessToken string) (map[string]string, error) {
	timestamp := time.Now().Unix()

	msgHash, err := commons.GenerateMessageHash(message, timestamp)
	if err != nil {
		return nil, err
	}
	return c.generateCredentials(msgHash, accessToken, timestamp)
}

func (c *EphemeralKey) generateCredentials(message []byte, accessToken string, timestamp int64) (map[string]string, error) {
	signature, err := commons.SignMessage(message, c.PrivateKey)
	if err != nil {
		return nil, err
	}

	fields := map[string]string{}

	fields["x-signature"] = hex.EncodeToString(signature)
	fields["x-identity"] = fmt.Sprintf("public key derived address: %s", hexutil.Encode(crypto.CompressPubkey(&c.PrivateKey.PublicKey)))
	fields["x-timestamp"] = strconv.FormatInt(timestamp, 10)
	fields["x-auth-type"] = "third-party"
	fields["x-access-token"] = accessToken

	return fields, nil
}

func completeRequest(r *http.Request, readFields func() (map[string]string, error)) error {
	fields, err := readFields()
	if err != nil {
		return err
	}

	for header, value := range fields {
		r.Header.Set(header, value)
	}

	return nil
}
