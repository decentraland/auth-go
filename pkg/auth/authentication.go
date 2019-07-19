package auth

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/signer/core"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/decentraland/auth-go/internal/utils"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

const certificatePattern = ".*Date: (.*) Expires: (.*)"
const identityEthBasedPattern = "decentraland:(.*)\\/temp\\/(.*)"

// Authenticate all requests
type AllowAllAuthnStrategy struct{}

func (s *AllowAllAuthnStrategy) Authenticate(r *AuthRequest) (Result, error) {
	return NewResultOutput(), nil
}

type SelfGrantedStrategy struct {
	RequestTolerance int64
}

// Validates the request credentials generated with the EphemeralKeys protocol
func (s *SelfGrantedStrategy) Authenticate(r *AuthRequest) (Result, error) {
	cred := r.Credentials
	requiredCredentials := []string{HeaderIdentity, HeaderTimestamp, HeaderCert, HeaderCertSignature, HeaderSignature, HeaderAuthType}
	if err := utils.ValidateRequiredCredentials(cred, requiredCredentials); err != nil {
		return nil, MissingCredentialsError{err.Error()}
	}

	if err := validateCertificateType(cred, "self-granted"); err != nil {
		return nil, err
	}

	tokens, err := utils.ParseTokensWithRegex(cred[HeaderIdentity], identityEthBasedPattern)
	if err != nil {
		return nil, err
	}

	if len(tokens) != 2 {
		return nil, InvalidCredentialError{"unable to extract required information from 'x-identity' header"}
	}

	certAddress := tokens[0]
	ephPbKey := tokens[1]

	if err = checkRequestExpiration(cred["x-timestamp"], s.RequestTolerance); err != nil {
		return nil, err
	}

	if err = validateRequestSignature(r, ephPbKey); err != nil {
		return nil, err
	}

	if err = validateCertificate(cred[HeaderCert], cred["x-certificate-signature"], certAddress); err != nil {
		return nil, err
	}

	res := NewResultOutput()
	res.AddUserID(certAddress)
	return res, nil
}

func abs(v int64) int64 {
	if v > 0 {
		return v
	}
	return -v
}

// Verifies request expiration
func checkRequestExpiration(timestamp string, ttl int64) error {
	t, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return InvalidCredentialError{"invalid timestamp"}
	}
	now := time.Now().Unix()
	if abs(now-t) > ttl {
		return ExpiredRequestError{"request expired"}
	}
	return nil
}

// Validates that the signature sent in the request was generated for the current request
func validateRequestSignature(r *AuthRequest, pubKey string) error {
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
		return InvalidCredentialError{fmt.Sprintf("unable to decode signature: %s", err.Error())}
	}

	key, err := hexutil.Decode(utils.FormatHexString(pubKey))
	if err != nil {
		return InvalidCredentialError{fmt.Sprintf("unable to decode publickey: %s", err.Error())}
	}

	if !secp256k1.VerifySignature(key, message, sigBytes) {
		return InvalidRequestSignatureError{"invalid Signature"}
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
		return InvalidCertificateError{"expired certificate"}
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

	decodedMsg, err := hexutil.Decode(cert)
	if err != nil {
		return err
	}
	certHash, _ := core.SignHash(decodedMsg)

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
		return InvalidCertificateError{"invalid certificate. Signature does not match the certificate and the given public key"}
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
		return InvalidCredentialError{"invalid credential type"}
	}
	return nil
}
