package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"sigsum.org/sigsum-go/pkg/client"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Signer struct {
	Identity string `json:"identity"`
	Issuer   string `json:"issuer"`
}

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

// DomainRecord is our GORM model for storing domain records.
type DomainRecord struct {
	Domain    string `gorm:"primaryKey"`
	Signers   string
	Threshold int
}

func main() {
	// Command-line flags.
	logURL := flag.String("log-url", "", "URL of the Sigsum log (e.g., https://poc.sigsum.org/jellyfish)")
	logKeyHex := flag.String("log-key", "", "Hex-encoded public key of the log")
	submitKeyHex := flag.String("submit-key", "", "Hex-encoded submit public key to filter leaves")
	dataServer := flag.String("data-server", "", "URL of the data server for payload retrieval (e.g., https://data.example.com)")
	startIndex := flag.Uint64("start-index", 0, "Index to start retrieving leaves from")
	batchSize := flag.Uint64("batch-size", 512, "Number of leaves to fetch in each batch")
	outputFile := flag.String("output", "output.bin", "Path to the output binary file")
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

	// Open (or create) SQLite database using GORM.
	db, err := gorm.Open(sqlite.Open("list.db"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	// Auto-migrate the schema for DomainRecord.
	if err := db.AutoMigrate(&DomainRecord{}); err != nil {
		log.Fatalf("failed to auto-migrate: %v", err)
	}

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
		// query the data server, verify the payload, and update the database.
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
			if computedLeafhash != leaf.Checksum {
				log.Fatalf("hash mismatch for leaf %s: computed %s but got %s", leafChecksumHex, hex.EncodeToString(computedLeafhash[:]), hex.EncodeToString(leaf.Checksum[:]))
			}

			if !types.VerifyLeafMessage(&targetKey, computedHash[:], &leaf.Signature) {
				log.Fatalf("payload signature verification failed for leaf %s, message = %s, signature = %s",
					leafChecksumHex, hex.EncodeToString(computedHash[:]), hex.EncodeToString(leaf.Signature[:]))
			}

			fmt.Printf("Leaf %s: payload verified successfully.\n", leafChecksumHex)

			// Process the action from the canonical payload.
			switch strings.ToLower(canonical.Action) {
			case "add":
				// Check if a record for the domain already exists.
				var record DomainRecord
				result := db.First(&record, "domain = ?", canonical.Domain)
				if result.Error == nil {
					log.Fatalf("domain %s already exists, cannot add", canonical.Domain)
				} else if result.Error != gorm.ErrRecordNotFound {
					log.Fatalf("failed to query database for domain %s: %v", canonical.Domain, result.Error)
				}
				// Insert new record.
				record = DomainRecord{
					Domain:    canonical.Domain,
					Signers:   canonical.Signers,
					Threshold: canonical.Threshold,
				}
				if err := db.Create(&record).Error; err != nil {
					log.Fatalf("failed to insert record for domain %s: %v", canonical.Domain, err)
				}
				fmt.Printf("Domain %s added successfully.\n", canonical.Domain)
			case "delete":
				// Check if the record exists.
				var record DomainRecord
				result := db.First(&record, "domain = ?", canonical.Domain)
				if result.Error != nil {
					if result.Error == gorm.ErrRecordNotFound {
						log.Fatalf("domain %s does not exist, cannot delete", canonical.Domain)
					}
					log.Fatalf("failed to query database for domain %s: %v", canonical.Domain, result.Error)
				}
				// Delete the record.
				if err := db.Delete(&record).Error; err != nil {
					log.Fatalf("failed to delete record for domain %s: %v", canonical.Domain, err)
				}
				fmt.Printf("Domain %s deleted successfully.\n", canonical.Domain)
			case "modify":
				log.Fatalf("modify action not implemented for domain %s", canonical.Domain)
			default:
				log.Fatalf("malicious payload: unknown action %s for domain %s", canonical.Action, canonical.Domain)
			}
		}
	}

	fmt.Println("All matching payloads verified and processed successfully.")
	fmt.Println("Proceeding to build the actual list.")

	var records []DomainRecord
	if err := db.Find(&records).Error; err != nil {
		log.Fatalf("failed to query database: %v", err)
	}

	var output []byte
	for _, rec := range records {
		domainHash := sha256.Sum256([]byte(rec.Domain))

		// Compute the policy hash.
		var signers []Signer
		if err := json.Unmarshal([]byte(rec.Signers), &signers); err != nil {
			log.Fatalf("failed to parse signers for domain %s: %v", rec.Domain, err)
		}

		for i := range signers {
			signers[i].Identity = strings.ToLower(signers[i].Identity)
			signers[i].Issuer = strings.ToLower(signers[i].Issuer)
		}

		sort.Slice(signers, func(i, j int) bool {
			if signers[i].Identity == signers[j].Identity {
				return signers[i].Issuer < signers[j].Issuer
			}
			return signers[i].Identity < signers[j].Identity
		})

		policy := map[string]interface{}{
			"x-sigstore-signers":   signers,
			"x-sigstore-threshold": rec.Threshold,
		}

		policyJSON, err := json.Marshal(policy)
		if err != nil {
			log.Fatalf("failed to marshal policy for domain %s: %v", rec.Domain, err)
		}
		policyHash := sha256.Sum256(policyJSON)

		output = append(output, domainHash[:]...)
		output = append(output, policyHash[:]...)
	}

	if err := os.WriteFile(*outputFile, output, 0644); err != nil {
		log.Fatalf("failed to write output file: %v", err)
	}
	fmt.Printf("Output written to %s (%d bytes, %d records)\n", *outputFile, len(output), len(records))
}
