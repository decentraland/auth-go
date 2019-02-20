package ethereum

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/rpc"
)

// EthClient is an interface to connect to the eth net
type EthClient interface {
	NetVersion() (string, error)
	ListAccounts() ([]string, error)
	Sign(message string, address string, pass string) (string, error)
	GetDefaultAccount() (string, error)
}

type EthClientImpl struct {
	client *rpc.Client
}

// NewEthClient creates a new Eth clien, if it fails to connect to the external resource, it will retrieve an error
func NewEthClient(location string) (EthClient, error) {
	c, err := rpc.Dial(location)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Unable to connect to Eth node: %s", err.Error()))
	}
	return &EthClientImpl{client: c}, nil
}

// NetVersion retrieves the current network id.
func (c *EthClientImpl) NetVersion() (string, error) {
	var r string
	if err := c.client.Call(&r, "net_version", []interface{}{}); err != nil {
		return "", err
	}
	return r, nil
}

// Returns a list of addresses owned by client.
func (c *EthClientImpl) ListAccounts() ([]string, error) {
	var r []string
	if err := c.client.Call(&r, "eth_accounts", []interface{}{}); err != nil {
		return nil, err
	}
	return r, nil
}

// Signs the message.
func (c *EthClientImpl) Sign(message string, address string, pass string) (string, error) {
	var r string
	if err := c.client.Call(&r, "personal_sign", message, address, pass); err != nil {
		return "", err
	}
	return r, nil
}

// GetDefaultAccount gets the default account (first on the list) to generate the Ephemeral keys
func (c *EthClientImpl) GetDefaultAccount() (string, error) {
	accounts, err := c.ListAccounts()
	if err != nil {
		return "", err
	}
	if len(accounts) < 1 {
		return "", errors.New("No Account found")
	}
	return accounts[0], nil
}
