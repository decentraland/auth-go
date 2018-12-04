package authentication

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/decentraland/auth-go/auth"
	"github.com/decentraland/auth-go/config"
	"github.com/decentraland/auth-go/utils"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const certificatePattern = ".*Date: (.*) Expires: (.*)"

type ephemeralKeysAuthentication struct {
	config *config.AuthConfig
}

func NewStrategy(c *config.AuthConfig) auth.AuthenticationStrategy {
	return &ephemeralKeysAuthentication{config: c}
}

// Validates the request credentials generated with the EphemeralKeys protocol
func (e *ephemeralKeysAuthentication) Authenticate(r *auth.AuthRequest) (bool, error) {
	cred := r.Credentials
	idHeader, err := utils.ExtractRequiredField(cred, "x-identity")
	if err != nil {
		return false, err
	}
	certAddress, ephPbKey, err := utils.ParseIdentity(idHeader)
	if err != nil {
		return false, err
	}

	if err = checkExpiration(cred, e.config.RequestAllowedTTL); err != nil {
		return false, err
	}

	if err = validateRequestSignature(r, ephPbKey); err != nil {
		return false, err
	}

	if err = validateCertificate(cred, certAddress); err != nil {
		return false, err
	}

	return true, nil
}

// Verifies request expiration
func checkExpiration(m map[string]string, ttl int64) error {
	timestamp, err := utils.ExtractRequiredField(m, "x-timestamp")
	if err != nil {
		return err
	}

	milliseconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return errors.New("invalid timestamp")
	}
	now := utils.GetCurrentTimestamp()
	if milliseconds > now || now-milliseconds > (ttl*1000) {
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

	signature, err := utils.ExtractRequiredField(cred, "x-signature")
	if err != nil {
		return err
	}

	if err = validateSignature(signature, msg, pubKey); err != nil {
		return err
	}
	return nil
}

// Verifies  that the given pubkey created signature over message.
func validateSignature(signature string, message []byte, pubKey string) error {
	valid, err := isValidSignature(utils.FormatHexString(signature), message, utils.FormatHexString(pubKey))
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("invalid Signature")
	}
	return nil
}

// Verify if the signature is valid for a given msg and public key
// The signature and the key should be hex strings
func isValidSignature(signature string, message []byte, pubKey string) (bool, error) {
	sigBytes, err := hexutil.Decode(signature)
	if err != nil {
		return false, err
	}

	key, err := hexutil.Decode(pubKey)
	verified := secp256k1.VerifySignature(key, message, sigBytes)
	return verified, nil
}

// Validates the information of the credentials created during the ephemeralKeys generation
func validateCertificate(m map[string]string, address string) error {
	certificate, err := utils.ExtractRequiredField(m, "x-certificate")
	if err != nil {
		return err
	}
	certSignature, err := utils.ExtractRequiredField(m, "x-certificate-signature")
	if err != nil {
		return err
	}

	if err = validateCertificateExpiration(certificate); err != nil {
		return err
	}

	if err = validateCertificateSignature(certificate, certSignature, address); err != nil {
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
