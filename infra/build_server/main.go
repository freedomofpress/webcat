package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/requests"
)

// TODO, in the future, this code should take in a trust policy, and verify the consistency

func main() {
	logURL := flag.String("log-url", "", "URL of the Sigsum log (e.g., https://poc.sigsum.org/jellyfish)")
	logKeyHex := flag.String("log-key", "", "Hex-encoded public key of the log")
	submitKeyHex := flag.String("submit-key", "", "Hex-encoded submit public key to filter leaves")
	startIndex := flag.Uint64("start-index", 0, "Index to start retrieving leaves from")
	batchSize := flag.Uint64("batch-size", 512, "Number of leaves to fetch in each batch")
	flag.Parse()

	if *logURL == "" || *logKeyHex == "" || *submitKeyHex == "" {
		flag.Usage()
		os.Exit(1)
	}

	logKey, err := crypto.PublicKeyFromHex(*logKeyHex)
	if err != nil {
		log.Fatalf("Error parsing submit key: %v", err)
	}

	targetKey, err := crypto.PublicKeyFromHex(*submitKeyHex)
	if err != nil {
		log.Fatalf("Error parsing submit key: %v", err)
	}

	targetKeyHash := crypto.HashBytes(targetKey[:])

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cfg := client.Config{
		URL:       *logURL,
		UserAgent: "webcat-list-builder",
	}

	client := client.New(cfg)

	treeHead, err := client.GetTreeHead(ctx)
	if err != nil {
		log.Fatalf("failed to get tree head: %v", err)
	}

	if !treeHead.SignedTreeHead.Verify(&logKey) {
		log.Fatalf("failed to verify tree head signature")
	}

	totalLeaves := treeHead.Size
	fmt.Printf("Total leaves in log: %d\n", totalLeaves)

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
		leaves, err := client.GetLeaves(ctx, req)
		if err != nil {
			log.Fatalf("error downloading leaves [%d, %d): %v", start, end, err)
		}

		// Process each downloaded leaf. Here we simply print it.
		for _, leaf := range leaves {
			if leaf.KeyHash == targetKeyHash {
				fmt.Println(hex.EncodeToString(leaf.Checksum[:]))
				fmt.Println(hex.EncodeToString(leaf.Signature[:]))
			}
		}
	}
}
