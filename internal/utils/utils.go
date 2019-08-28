package utils

import (
	"fmt"
	"regexp"
	"strings"
)

// ValidateRequiredCredentials validates all required credentials are present
func ValidateRequiredCredentials(m map[string]string, keys []string) error {
	var missing []string
	for _, key := range keys {
		if _, ok := m[key]; !ok {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required credentials: %s", strings.Join(missing, ", "))
	}
	return nil
}

// FormatHexString adds the Ox prefix to the string if not present
func FormatHexString(toPad string) string {
	if strings.HasPrefix(toPad, "0x") {
		return toPad
	}
	return "0x" + toPad
}

// RemoveHexPrefix removes the Ox prefix from the string if present
func RemoveHexPrefix(value string) string {
	if !strings.HasPrefix(value, "0x") {
		return value
	}
	return value[2:]
}

// ParseTokensWithRegex retrieves the Address that generated the certificate
// and the public ephemeral key from the identity header
func ParseTokensWithRegex(idHeader string, pattern string) ([]string, error) {
	idRegex := *regexp.MustCompile(pattern)
	if !idRegex.MatchString(idHeader) {
		return nil, fmt.Errorf("malformed 'x-identity' header: %s", idHeader)
	}
	matches := idRegex.FindAllStringSubmatch(idHeader, -1)
	return matches[0][1:], nil
}
