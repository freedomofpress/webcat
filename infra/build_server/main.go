package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

// TransparencyEntry is the JSON structure returned by the data server.
type TransparencyEntry struct {
	CreatedAt string `json:"createdAt"`
	Hash      string `json:"hash"`
	Payload   string `json:"payload"`
	Proof     string `json:"proof"`
	Signature string `json:"signature"`
}

// CanonicalPayload represents the canonical payload used during signing.
type CanonicalPayload struct {
	Domain           string `json:"domain"`
	Action           string `json:"action"`
	Signers          string `json:"signers"`
	Threshold        int    `json:"threshold"`
	ConfirmationDate string `json:"confirmation_date"`
}

func main() {
	// Command-line flags.
	logURL := flag.String("log-url", "", "URL of the Sigsum log (e.g., https://poc.sigsum.org/jellyfish)")
	logKeyHex := flag.String("log-key", "", "Hex-encoded public key of the log")
	submitKeyHex := flag.String("submit-key", "", "Hex-encoded submit public key to filter leaves")
	dataServer := flag.String("data-server", "", "URL of the data server for payload retrieval (e.g., https://data.example.com)")
	startIndex := flag.Uint64("start-index", 0, "Index to start retrieving leaves from")
	batchSize := flag.Uint64("batch-size", 512, "Number of leaves to fetch in each batch")
	flag.Parse()

	if *logURL == "" || *logKeyHex == "" || *submitKeyHex == "" || *dataServer == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Parse public keys.
	logKey, err := crypto.PublicKeyFromHex(*logKeyHex)
	if err != nil {
		log.Fatalf("Error parsing log key: %v", err)
	}

	targetKey, err := crypto.PublicKeyFromHex(*submitKeyHex)
	if err != nil {
		log.Fatalf("Error parsing submit key: %v", err)
	}

	// Compute the hash of the target submit key.
	targetKeyHash := crypto.HashBytes(targetKey[:])

	// Create a context.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create the Sigsum client.
	cfg := client.Config{
		URL:       *logURL,
		UserAgent: "webcat-list-builder",
	}
	cli := client.New(cfg)

	// Retrieve the tree head.
	treeHead, err := cli.GetTreeHead(ctx)
	if err != nil {
		log.Fatalf("failed to get tree head: %v", err)
	}

	// Verify the tree head signature.
	if !treeHead.SignedTreeHead.Verify(&logKey) {
		log.Fatalf("failed to verify tree head signature")
	}
	fmt.Println("Tree head signature verified.")

	totalLeaves := treeHead.Size
	fmt.Printf("Total leaves in log: %d\n", totalLeaves)

	// Process leaves in batches.
	for start := *startIndex; start < totalLeaves; start += uint64(*batchSize) {
		end := start + uint64(*batchSize)
		if end > totalLeaves {
			end = totalLeaves
		}
		fmt.Printf("Downloading leaves [%d, %d)...\n", start, end)

		req := requests.Leaves{
			StartIndex: start,
			EndIndex:   end,
		}
		leaves, err := cli.GetLeaves(ctx, req)
		if err != nil {
			log.Fatalf("error downloading leaves [%d, %d): %v", start, end, err)
		}

		// For each downloaded leaf that matches our target submit key,
		// query the data server and verify the payload.
		for _, leaf := range leaves {
			if leaf.KeyHash != targetKeyHash {
				continue
			}

			// Build the URL: <data-server>/transparency/<leaf_checksum>
			leafChecksumHex := hex.EncodeToString(leaf.Checksum[:])
			url := fmt.Sprintf("%s/transparency/%s", *dataServer, leafChecksumHex)
			fmt.Printf("Querying data server for leaf %s...\n", leafChecksumHex)

			resp, err := http.Get(url)
			if err != nil {
				log.Fatalf("failed to query data server for leaf %s: %v", leafChecksumHex, err)
			}
			if resp.StatusCode != http.StatusOK {
				log.Fatalf("data server returned non-OK status for leaf %s: %s", leafChecksumHex, resp.Status)
			}

			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				log.Fatalf("failed to read response for leaf %s: %v", leafChecksumHex, err)
			}

			var entry TransparencyEntry
			if err := json.Unmarshal(body, &entry); err != nil {
				log.Fatalf("failed to parse JSON for leaf %s: %v", leafChecksumHex, err)
			}

			// Reproduce the canonical payload by unmarshaling and re-marshaling.
			var canonical CanonicalPayload
			if err := json.Unmarshal([]byte(entry.Payload), &canonical); err != nil {
				log.Fatalf("failed to unmarshal canonical payload for leaf %s: %v", leafChecksumHex, err)
			}
			canonicalBytes, err := json.Marshal(canonical)
			if err != nil {
				log.Fatalf("failed to re-marshal canonical payload for leaf %s: %v", leafChecksumHex, err)
			}

			// Compute the hash using the same function originally.
			computedHash := crypto.HashBytes(canonicalBytes)
			if hex.EncodeToString(computedHash[:]) != entry.Hash {
				log.Fatalf("hash mismatch for leaf %s: computed %s but got %s", leafChecksumHex, hex.EncodeToString(computedHash[:]), entry.Hash)
			}

			if hex.EncodeToString(leaf.Signature[:]) != entry.Signature {
				log.Fatalf("signature mismatch for leaf %s: expected %s but got %s", leafChecksumHex, hex.EncodeToString(leaf.Signature[:]), entry.Signature)
			}

			computedLeafhash := crypto.HashBytes(computedHash[:])
			if hex.EncodeToString(computedHash[:]) != entry.Hash {
				log.Fatalf("hash mismatch for payload %s: computed %s but got %s", leafChecksumHex, hex.EncodeToString(computedHash[:]), entry.Hash)
			}

			if computedLeafhash != leaf.Checksum {
				log.Fatalf("hash mismatch for leaf %s: computed %s but got %s", leafChecksumHex, leafChecksumHex, hex.EncodeToString(computedLeafhash[:]))
			}

			if !types.VerifyLeafMessage(&targetKey, computedHash[:], &leaf.Signature) {
				log.Fatalf("payload signature verification failed for leaf %s, message = %s, signature = %s", leafChecksumHex, hex.EncodeToString(computedHash[:]), hex.EncodeToString(leaf.Signature[:]))
			}

			fmt.Printf("Leaf %s: payload verified successfully.\n", leafChecksumHex)
		}
	}

	fmt.Println("All matching payloads verified successfully.")
}
