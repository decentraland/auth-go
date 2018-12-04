package utils

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const identityPattern = "decentraland:(.*)\\/temp\\/(.*)"

// Extracts headers values. If the key is not present retrieves an error
func ExtractRequiredField(m map[string]string, key string) (string, error) {
	r := m[key]
	if len(r) == 0 {
		return "", fmt.Errorf("missing required credential: %s", key)
	}
	return r, nil
}

// Adds the Ox prefix to the string if not present
func FormatHexString(toPad string) string {
	if strings.HasPrefix(toPad, "0x") {
		return toPad
	}
	return "0x" + toPad
}

func RemoveHexPrefix(value string) string {
	if !strings.HasPrefix(value, "0x") {
		return value
	}
	return value[2:]
}

// Timestamp in milliseconds
func GetCurrentTimestamp() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

// Reads the request content into a byte array
func ReadRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	b, err := r.GetBody()
	if err != nil {
		return nil, err
	}
	content, err := ioutil.ReadAll(b)
	if err != nil {
		return nil, err
	}
	return content, nil
}

// Retrieves the Address that generated the certificate  and the public ephemeral key from the identity header
func ParseIdentity(idHeader string) (string, string, error) {
	idRegex := *regexp.MustCompile(identityPattern)
	if !idRegex.MatchString(idHeader) {
		return "", "", fmt.Errorf("malformed 'x-identity' header: %s", idHeader)
	}
	matches := idRegex.FindAllStringSubmatch(idHeader, -1)
	return matches[0][1], matches[0][2], nil
}
