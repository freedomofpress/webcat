package common

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func CheckDNS(domain string) ([]net.IP, error) {
	hostname := strings.TrimPrefix(strings.TrimPrefix(domain, "https://"), "http://")
	ips, err := net.LookupIP(hostname)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("DNS lookup failed for %s", hostname)
	}
	return ips, nil
}

func CheckHTTPS(domain string) (http.Header, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(domain)
	if err != nil {
		return nil, fmt.Errorf("HTTPS check failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTPS check returned status %d", resp.StatusCode)
	}
	return resp.Header, nil
}

// validateSigstoreHeaders validates the required headers from the HTTPS response.
// It expects:
//   - Header "x-sigstore-signers": a JSON array of objects where each object has exactly
//     two keys: "identity" and "issuer". "identity" must be a valid email, and "issuer" must
//     be one of the allowed values.
//   - Header "x-sigstore-threshold": a string representing an integer that is less than or
//     equal to the number of signers.
func validateSigstoreHeaders(headers http.Header) error {
	signersStr := headers.Get("x-sigstore-signers")
	thresholdStr := headers.Get("x-sigstore-threshold")
	if signersStr == "" {
		return fmt.Errorf("missing required header: x-sigstore-signers")
	}
	if thresholdStr == "" {
		return fmt.Errorf("missing required header: x-sigstore-threshold")
	}

	// Parse the signers JSON.
	var signers []map[string]string
	if err := json.Unmarshal([]byte(signersStr), &signers); err != nil {
		return fmt.Errorf("invalid x-sigstore-signers JSON: %w", err)
	}

	// Check the number of signers.
	n := len(signers)
	if n < 1 || n > 16 {
		return fmt.Errorf("number of signers must be between 1 and 16; got %d", n)
	}

	// Define allowed issuer values.
	validIssuers := map[string]bool{
		"https://accounts.google.com":       true,
		"https://login.microsoftonline.com": true,
		"https://github.com/login/oauth":    true,
		"https://gitlab.com":                true,
	}

	// Define a simple regex for validating email addresses.
	emailRegex := regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

	// Validate each signer.
	for i, signer := range signers {
		// Ensure the signer has exactly the keys "identity" and "issuer".
		if len(signer) != 2 {
			return fmt.Errorf("signer %d must contain exactly 'identity' and 'issuer' fields", i)
		}
		identity, ok := signer["identity"]
		if !ok {
			return fmt.Errorf("signer %d is missing the 'identity' field", i)
		}
		issuer, ok := signer["issuer"]
		if !ok {
			return fmt.Errorf("signer %d is missing the 'issuer' field", i)
		}
		if !emailRegex.MatchString(identity) {
			return fmt.Errorf("signer %d has an invalid email address: %s", i, identity)
		}
		if !validIssuers[issuer] {
			return fmt.Errorf("signer %d has an invalid issuer: %s", i, issuer)
		}
	}

	// Parse threshold.
	threshold, err := strconv.Atoi(thresholdStr)
	if err != nil {
		return fmt.Errorf("x-sigstore-threshold is not a valid integer: %w", err)
	}
	if threshold > n {
		return fmt.Errorf("x-sigstore-threshold (%d) is greater than the number of signers (%d)", threshold, n)
	}

	return nil
}
