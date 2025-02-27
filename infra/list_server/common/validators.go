package common

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

func ValidateRawHostname(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", fmt.Errorf("empty hostname")
	}

	if strings.Contains(input, "://") {
		return "", fmt.Errorf("hostname must be raw, no scheme allowed")
	}

	if strings.Contains(input, "/") {
		return "", fmt.Errorf("hostname must be raw, no path allowed")
	}

	if strings.Contains(input, ":") {
		return "", fmt.Errorf("hostname must be raw, no port allowed")
	}

	ascii, err := idna.ToASCII(input)
	if err != nil {
		return "", fmt.Errorf("failed to convert hostname to ASCII: %v", err)
	}

	// Reject hostnames that start with a dot.
	if strings.HasPrefix(ascii, ".") || strings.HasSuffix(ascii, ".") {
		return "", fmt.Errorf("hostname %q must not have a leading or ending dot", ascii)
	}

	if !strings.Contains(ascii, ".") || strings.Contains(ascii, "..") {
		return "", fmt.Errorf("hostname %q does not appear to be valid", ascii)
	}

	ascii = strings.ToLower(ascii)
	return ascii, nil
}

func CheckDNS(domain string) ([]net.IP, error) {
	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("DNS lookup failed for %s", domain)
	}
	return ips, nil
}

func CheckHTTPS(domain string) (http.Header, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://" + domain)
	if err != nil {
		return nil, fmt.Errorf("HTTPS check failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTPS check returned status %d", resp.StatusCode)
	}
	return resp.Header, nil
}

func NormalizeSigners(raw string) (string, int, error) {
	// Unmarshal into a slice of Signer structs.
	var signers []Signer
	if err := json.Unmarshal([]byte(raw), &signers); err != nil {
		return "", 0, fmt.Errorf("invalid x-sigstore-signers JSON: %w", err)
	}

	n := len(signers)
	if n < 1 || n > 16 {
		return "", 0, fmt.Errorf("number of signers must be between 1 and 16; got %d", n)
	}

	validIssuers := map[string]bool{
		"https://accounts.google.com":       true,
		"https://login.microsoftonline.com": true,
		"https://github.com/login/oauth":    true,
		"https://gitlab.com":                true,
	}

	emailRegex := regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

	for i := range signers {
		signers[i].Identity = strings.TrimSpace(signers[i].Identity)
		signers[i].Issuer = strings.TrimSpace(signers[i].Issuer)
		signers[i].Identity = strings.ToLower(signers[i].Identity)
		signers[i].Issuer = strings.ToLower(signers[i].Issuer)

		if !emailRegex.MatchString(signers[i].Identity) {
			return "", 0, fmt.Errorf("signer %d has an invalid email address: %s", i, signers[i].Identity)
		}
		if !validIssuers[signers[i].Issuer] {
			return "", 0, fmt.Errorf("signer %d has an invalid issuer: %s", i, signers[i].Issuer)
		}
	}

	// Sort signers deterministically (by identity, then issuer).
	sort.Slice(signers, func(i, j int) bool {
		if signers[i].Identity == signers[j].Identity {
			return signers[i].Issuer < signers[j].Issuer
		}
		return signers[i].Identity < signers[j].Identity
	})

	normalizedBytes, err := json.Marshal(signers)
	if err != nil {
		return "", 0, fmt.Errorf("failed to marshal normalized signers: %w", err)
	}

	return string(normalizedBytes), len(signers), nil
}

func ValidateAndNormalizeSigstoreHeaders(headers http.Header) (normalizedSigners string, threshold int, err error) {
	signersStr := headers.Get("x-sigstore-signers")
	thresholdStr := headers.Get("x-sigstore-threshold")
	webcatAction := headers.Get("x-webcat-action")

	if strings.TrimSpace(signersStr) == "" {
		return "", 0, fmt.Errorf("missing required header: x-sigstore-signers")
	}
	if strings.TrimSpace(thresholdStr) == "" {
		return "", 0, fmt.Errorf("missing required header: x-sigstore-threshold")
	}
	if strings.TrimSpace(webcatAction) == "" {
		return "", 0, fmt.Errorf("missing required header: x-webcat-action")
	}
	webcatAction = strings.ToLower(webcatAction)
	if webcatAction != "add" && webcatAction != "modify" && webcatAction != "delete" {
		return "", 0, fmt.Errorf("invalid x-webcat-action value: must be ADD, MODIFY, or DELETE")
	}

	normalizedSigners, n, err := NormalizeSigners(signersStr)
	if err != nil {
		return "", 0, err
	}

	threshold, err = strconv.Atoi(thresholdStr)
	if err != nil {
		return "", 0, fmt.Errorf("x-sigstore-threshold is not a valid integer: %w", err)
	}
	if threshold > n {
		return "", 0, fmt.Errorf("x-sigstore-threshold (%d) is greater than the number of signers (%d)", threshold, n)
	}

	return normalizedSigners, threshold, nil
}
