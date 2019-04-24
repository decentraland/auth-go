package authentication

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/decentraland/auth-go/internal/utils"
	"github.com/decentraland/auth-go/pkg/auth"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const certificatePattern = ".*Date: (.*) Expires: (.*)"
const identityPattern = "decentraland:(.*)\\/temp\\/(.*)"

// Authenticate all requests
type AllowAllStrategy struct{}

func (s *AllowAllStrategy) Authenticate(r *auth.AuthRequest) (bool, error) {
	return true, nil
}

type SelfGrantedStrategy struct {
	RequestLifeSpan int64
}

// Validates the request credentials generated with the EphemeralKeys protocol
func (s *SelfGrantedStrategy) Authenticate(r *auth.AuthRequest) (bool, error) {
	cred := r.Credentials
	requiredCredentials := []string{auth.HeaderIdentity, auth.HeaderTimestamp, auth.HeaderCert, auth.HeaderCertSignature, auth.HeaderSignature, auth.HeaderAuthType}
	if err := utils.ValidateRequiredCredentials(cred, requiredCredentials); err != nil {
		return false, err
	}

	if err := validateCertificateType(cred, "self-granted"); err != nil {
		return false, err
	}

	tokens, err := utils.ParseTokensWithRegex(cred[auth.HeaderIdentity], identityPattern)
	if err != nil {
		return false, err
	}

	if len(tokens) != 2 {
		return false, fmt.Errorf("unable to exctract required information from 'x-identity' header")
	}

	certAddress := tokens[0]
	ephPbKey := tokens[1]

	if err = checkRequestExpiration(cred["x-timestamp"], s.RequestLifeSpan); err != nil {
		return false, err
	}

	if err = validateRequestSignature(r, ephPbKey); err != nil {
		return false, err
	}

	if err = validateCertificate(cred[auth.HeaderCert], cred["x-certificate-signature"], certAddress); err != nil {
		return false, err
	}

	return true, nil
}

// Verifies request expiration
func checkRequestExpiration(timestamp string, ttl int64) error {
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return errors.New("invalid timestamp")
	}
	now := time.Now().Unix()
	if seconds > now || now-seconds > ttl {
		return errors.New("request expired")
	}
	return nil
}

// Validates that the signature sent in the request was generated for the current request
func validateRequestSignature(r *auth.AuthRequest, pubKey string) error {
	cred := r.Credentials
	msg, err := r.Hash()
	if err != nil {
		return err
	}

	if err = validateSignature(cred["x-signature"], msg, pubKey); err != nil {
		return err
	}
	return nil
}

// Verifies  that the given pubkey created signature over message.
func validateSignature(signature string, message []byte, pubKey string) error {
	sigBytes, err := hexutil.Decode(utils.FormatHexString(signature))
	if err != nil {
		return err
	}

	key, err := hexutil.Decode(utils.FormatHexString(pubKey))
	if err != nil {
		return err
	}

	if !secp256k1.VerifySignature(key, message, sigBytes) {
		return errors.New("invalid Signature")
	}
	return nil
}

// Validates the information of the credentials created during the ephemeralKeys generation
func validateCertificate(certificate string, certSignature string, address string) error {
	if err := validateCertificateExpiration(certificate); err != nil {
		return err
	}

	if err := validateCertificateSignature(certificate, certSignature, address); err != nil {
		return err
	}

	return nil
}

// Verifies if the certificate in the request has expired
func validateCertificateExpiration(certificate string) error {
	bs, err := hex.DecodeString(utils.RemoveHexPrefix(certificate))
	if err != nil {
		return err
	}
	cert := string(bs)

	_, expDate, err := extractDatesFromCertificate(cert)
	if err != nil {
		return err
	}

	if time.Now().UTC().After(*expDate) {
		return errors.New("expired certificate")
	}
	return nil
}

// Checks that the certificate and it's signature matches, extracting the pubKey from the
// Signature + cert hash, and comparing that to the address sent in in the request
func validateCertificateSignature(cert string, signature string, address string) error {
	requestAddress, err := hexutil.Decode(address)
	if err != nil {
		return err
	}

	sb, err := decodeCertificateSignature(signature)
	if err != nil {
		return err
	}

	certHash, err := getPersonalSignFormattedMessage(cert)
	if err != nil {
		return err
	}

	publicKeyBytes, err := crypto.Ecrecover(certHash, sb)
	if err != nil {
		return err
	}

	// Verify verify given public key created signature over hash
	verified := crypto.VerifySignature(publicKeyBytes, certHash, sb[:64])

	publicKey, err := crypto.UnmarshalPubkey(publicKeyBytes)
	if err != nil {
		return err
	}

	// Obtain the derived address from the pub key to compare against the request data
	derivedAddress := crypto.PubkeyToAddress(*publicKey)

	if !(verified && bytes.Equal(derivedAddress.Bytes(), requestAddress)) {
		return fmt.Errorf("invalid certificate. Signature does not match the certificate and the given public key")
	}
	return nil
}

func extractDatesFromCertificate(cert string) (*time.Time, *time.Time, error) {
	cert = strings.Replace(cert, "\n", " ", -1)
	datesRegex := *regexp.MustCompile(certificatePattern)
	if !datesRegex.MatchString(cert) {
		return nil, nil, errors.New("invalid certificate")
	}

	dates := datesRegex.FindAllStringSubmatch(cert, -1)
	credentialDate, err := time.Parse(time.RFC3339, dates[0][1])
	if err != nil {
		return nil, nil, err
	}
	expirationDate, err := time.Parse(time.RFC3339, dates[0][2])
	if err != nil {
		return nil, nil, err
	}

	return &credentialDate, &expirationDate, nil
}

/**
 * The sign method calculates an Ethereum specific signature with:
 * sign(keccack256("\x19Ethereum Signed Message:\n" + len(message) + message))).
 * This methods adds this prefix to the message to make it equivalent to the
 * Message eth node ends up signing
 */
func getPersonalSignFormattedMessage(msg string) ([]byte, error) {
	mb, err := hexutil.Decode(msg)
	if err != nil {
		return nil, err
	}
	return crypto.Keccak256([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(mb), mb))), nil
}

func decodeCertificateSignature(signature string) ([]byte, error) {
	sigBytes, err := hexutil.Decode(utils.FormatHexString(signature))
	if err != nil {
		return nil, err
	}
	if len(sigBytes) != 65 {
		return nil, errors.New("invalid certificate signature")
	}

	if sigBytes[64] == 27 || sigBytes[64] == 28 {
		sigBytes[64] -= 27
	}
	return sigBytes, nil
}

func validateCertificateType(cred map[string]string, credType string) error {
	authType := cred["x-auth-type"]
	if strings.ToLower(authType) != strings.ToLower(credType) {
		return errors.New("invalid credential type")
	}
	return nil
}
