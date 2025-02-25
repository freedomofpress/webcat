package common

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/policy"
)

// ComputeSHA256 returns the SHA-256 hash of the input string as a hexadecimal string.
func ComputeSHA256(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}

// SavePrivateKey writes a crypto.PrivateKey as a hex-encoded string to the specified file.
func SavePrivateKey(path string, priv crypto.PrivateKey) error {
	data := hex.EncodeToString(priv[:])
	return os.WriteFile(path, []byte(data), 0600)
}

// SavePublicKey writes a crypto.PublicKey as a hex-encoded string to the specified file.
func SavePublicKey(path string, pub crypto.PublicKey) error {
	data := hex.EncodeToString(pub[:])
	return os.WriteFile(path, []byte(data), 0644)
}

// ReadPrivateKeyFile reads a file containing a hex-encoded private key
// and returns the crypto.PrivateKey.
func ReadPrivateKeyFile(path string) (crypto.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return crypto.PrivateKey{}, err
	}
	var priv crypto.PrivateKey
	// Use the provided decodeHex logic (or simply hex.DecodeString).
	data, err := hex.DecodeString(string(b))
	if err != nil {
		return crypto.PrivateKey{}, fmt.Errorf("failed to decode private key hex: %w", err)
	}
	if len(data) != len(priv) {
		return crypto.PrivateKey{}, fmt.Errorf("unexpected key length: got %d, expected %d", len(data), len(priv))
	}
	copy(priv[:], data)
	return priv, nil
}

func EnsureSigsumKeyExists() crypto.Signer {
	keyPath := os.Getenv("SIGSUM_PRIVATE_KEY_PATH")
	if keyPath == "" {
		log.Fatal("Environment variable SIGSUM_PRIVATE_KEY_PATH is required")
	}

	// Check if the key file exists.
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		log.Printf("Key file not found at %s. Generating a new key pair...", keyPath)
		pub, signer, err := crypto.NewKeyPair()
		if err != nil {
			log.Fatalf("Generating key pair failed: %v", err)
		}
		if err := SavePrivateKey(keyPath, signer.Private()); err != nil {
			log.Fatalf("Writing private key file failed: %v", err)
		}
		if err := SavePublicKey(keyPath+".pub", pub); err != nil {
			log.Fatalf("Writing public key file failed: %v", err)
		}
		log.Printf("New key pair generated and saved at %s and %s.pub", keyPath, keyPath)
		return signer
	} else {
		// If the key file exists, attempt to load it.
		priv, err := ReadPrivateKeyFile(keyPath)
		if err != nil {
			log.Fatalf("Reading key file failed: %v", err)
		}
		// Create a signer from the loaded private key.
		return crypto.NewEd25519Signer(&priv)
	}
}

func EnsureSigsumPolicyExists() policy.Policy {
	path := os.Getenv("SIGSUM_LOG_POLICY_PATH")
	if strings.TrimSpace(path) == "" {
		log.Fatal("Environment variable SIGSUM_LOG_POLICY_PATH is required")
	}
	pol, err := policy.ReadPolicyFile(path)
	if err != nil {
		log.Fatalf("Failed to read policy file at %s: %v", path, err)
	}
	return *pol
}
