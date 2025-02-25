package common

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/looplab/fsm"
	"gorm.io/gorm"
	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/submit"
	"sigsum.org/sigsum-go/pkg/types"
)

type Signer struct {
	Identity string `json:"identity"`
	Issuer   string `json:"issuer"`
}

type CanonicalPayload struct {
	Domain    string `json:"domain"`
	Action    string `json:"action"`    // e.g., "add", "modify", or "delete" (lowercase)
	Signers   string `json:"signers"`   // a slice of signer objects, each with only identity and issuer
	Threshold int    `json:"threshold"` // integer from x-sigstore-threshold
	//ConfirmationEmail string `json:"confirmation_email"` // e.g., "info@example.com"
	ConfirmationDate string `json:"confirmation_date"` // RFC3339 format date
}

// FSM states:
const (
	StateIngested             = "ingested"
	StateDNSChecked           = "dns_checked"
	StateHeadersValid         = "headers_valid"
	StateListChecked          = "list_checked"
	StateAwaitingConfirmation = "awaiting_confirmation"
	StateConfirmed            = "confirmed"
	StatePayloadSigned        = "payload_signed"
	StateSigsumSubmitted      = "sigsum_submitted"
	StateCompleted            = "completed"
	StateFailed               = "failed"
)

func newSubmissionFSM(initialState string) *fsm.FSM {
	return fsm.NewFSM(
		initialState,
		fsm.Events{
			{Name: "checkDNS", Src: []string{StateIngested}, Dst: StateDNSChecked},
			{Name: "checkHTTPS", Src: []string{StateDNSChecked}, Dst: StateHeadersValid},
			{Name: "checkList", Src: []string{StateHeadersValid}, Dst: StateListChecked},
			{Name: "sendValidation", Src: []string{StateListChecked}, Dst: StateAwaitingConfirmation},
			{Name: "confirm", Src: []string{StateAwaitingConfirmation}, Dst: StateConfirmed},
			{Name: "signPayload", Src: []string{StateConfirmed}, Dst: StatePayloadSigned},
			{Name: "submitSigsum", Src: []string{StatePayloadSigned}, Dst: StateSigsumSubmitted},
			{Name: "complete", Src: []string{StateSigsumSubmitted}, Dst: StateCompleted},
			{Name: "fail", Src: []string{
				StateIngested, StateDNSChecked, StateHeadersValid,
				StateListChecked, StateAwaitingConfirmation, StateConfirmed,
				StatePayloadSigned, StateSigsumSubmitted,
			}, Dst: StateFailed},
		},
		fsm.Callbacks{
			"enter_state": func(e *fsm.Event) {
				log.Printf("FSM transitioned: %s -> %s", e.Src, e.Dst)
			},
		},
	)
}

func ProcessSubmissionFSM(sub *Submission, signer crypto.Signer, policy policy.Policy, confirmationMode string) {
	// Create an in-memory FSM using the current persisted state.
	machine := newSubmissionFSM(sub.Status)

	// updateState updates the submission's state in the DB and appends a log entry.
	updateState := func(newState string) {
		sub.Status = newState
		DB.Save(sub)
		AppendLog(sub, fmt.Sprintf("State updated to '%s'", newState))
	}

	var respHeaders http.Header
	var err error

	// --- Step 1: DNS Check ---
	if sub.Status == StateIngested {
		if err := machine.Event("checkDNS"); err != nil {
			AppendLog(sub, "DNS check transition error: "+err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}

		domain, err := ValidateRawHostname(sub.Domain)
		if err != nil {
			AppendLog(sub, "Domain submitted is invalid"+err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}
		ips, err := net.LookupIP(domain)
		if err != nil || len(ips) == 0 {
			AppendLog(sub, "DNS lookup failed")
			machine.Event("fail")
			updateState(machine.Current())
			return
		}
		sub.Domain = domain
		updateState(StateHeadersValid)
		AppendLog(sub, fmt.Sprintf("DNS lookup successful: %v", ips))
		updateState(machine.Current())
	}

	if sub.Status == StateDNSChecked {
		if err := machine.Event("checkHTTPS"); err != nil {
			AppendLog(sub, "HTTPS check transition error: "+err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}
		respHeaders, err = CheckHTTPS(sub.Domain)
		if err != nil {
			AppendLog(sub, err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}
		normalizedSigners, threshold, err := ValidateAndNormalizeSigstoreHeaders(respHeaders)
		if err != nil {
			AppendLog(sub, "Header validation failed: "+err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}
		AppendLog(sub, "HTTPS check and header validation successful")
		// Persist the critical header values.
		sub.SigstoreSigners = normalizedSigners
		sub.SigstoreThreshold = threshold
		sub.WebcatAction = strings.ToLower(respHeaders.Get("x-webcat-action"))
		// Now update the state to HeadersValid.
		updateState(StateHeadersValid)
	}

	// --- Step 4: List Database Check (simulate) ---
	if sub.Status == StateHeadersValid {
		if err := machine.Event("checkList"); err != nil {
			AppendLog(sub, "List check transition error: "+err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}
		var listEntry ListEntry
		err = DB.First(&listEntry, "domain = ?", sub.Domain).Error
		if err == nil && sub.WebcatAction == "add" {
			AppendLog(sub, "Error: domain already exists in list; cannot add duplicate")
			machine.Event("fail")
			updateState(machine.Current())
			return
		} else if errors.Is(err, gorm.ErrRecordNotFound) && (sub.WebcatAction == "delete" || sub.WebcatAction == "modify") {
			AppendLog(sub, "Error: domain does not exists; cannot delete or modify")
			machine.Event("fail")
			updateState(machine.Current())
			return
		} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			AppendLog(sub, "Error: could not query the list "+err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}

		AppendLog(sub, "List database check passed")
		updateState(machine.Current())
	}

	// --- Step 5: Send Validation ---
	if sub.Status == StateListChecked {
		if err := machine.Event("sendValidation"); err != nil {
			AppendLog(sub, "Send validation transition error: "+err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}

		if confirmationMode == "email" {
			rawToken := uuid.New().String()
			fmt.Println("Confirmation token:", rawToken)
			hashedToken := ComputeSHA256(rawToken)
			sub.ValidationToken = hashedToken
			// Set the wait deadline to 12 hours.
			waitUntil := time.Now().Add(12 * time.Hour)
			sub.WaitUntil = &waitUntil
			AppendLog(sub, "Validation email sent; waiting for confirmation until "+waitUntil.Format(time.RFC3339))
			updateState(machine.Current())
			// In email mode, processing will pause here waiting for external confirmation.
			return
		} else if confirmationMode == "recheck" {
			// RECHECK MODE: simply set a wait deadline.
			waitUntil := time.Now().Add(1 * time.Minute)
			sub.WaitUntil = &waitUntil
			AppendLog(sub, "Recheck mode: waiting until "+waitUntil.Format(time.RFC3339)+" to re-fetch headers for auto-confirmation")
			updateState(machine.Current())
			return
		}
	}

	// --- Step 5b: Awaiting Confirmation ---
	if sub.Status == StateAwaitingConfirmation {
		if sub.WaitUntil != nil && time.Now().Before(*sub.WaitUntil) {
			// Too much log spam
			//	AppendLog(sub, "Still waiting for confirmation; will re-check later")
			return
		}
		// The waiting period has expired. Now decide what to do based on confirmation mode.
		if confirmationMode == "recheck" {
			// In recheck mode, re-fetch headers and compare them to the persisted values.
			newHeaders, err := CheckHTTPS(sub.Domain)
			if err != nil {
				AppendLog(sub, "Error re-fetching HTTPS headers: "+err.Error())
				machine.Event("fail")
				updateState(machine.Current())
				return
			}
			// We are not checking the list again because as long as this submission is pending
			// No new one can be submitted
			newNormalizedSigners, newThreshold, err := ValidateAndNormalizeSigstoreHeaders(newHeaders)
			if err != nil {
				AppendLog(sub, "Second header validation failed: "+err.Error())
				machine.Event("fail")
				updateState(machine.Current())
				return
			}
			if newNormalizedSigners != sub.SigstoreSigners ||
				newThreshold != sub.SigstoreThreshold ||
				strings.ToLower(newHeaders.Get("x-webcat-action")) != sub.WebcatAction {
				AppendLog(sub, "Header re-check failed: current headers do not match initial ones")
				machine.Event("fail")
				updateState(machine.Current())
				return
			}
			AppendLog(sub, "Header re-check successful; auto-confirming submission")
			if err := machine.Event("confirm"); err != nil {
				AppendLog(sub, "Auto-confirm transition error: "+err.Error())
				machine.Event("fail")
				updateState(machine.Current())
				return
			}
			updateState(machine.Current())
		} else {
			// In email mode, if the waiting period expires without confirmation, we mark as failed.
			AppendLog(sub, "Waiting period expired without external confirmation")
			machine.Event("fail")
			updateState(machine.Current())
			return
		}
	}
	// --- Step 6: Process Confirmation ---
	if sub.Status == StateConfirmed {
		if err := machine.Event("signPayload"); err != nil {
			AppendLog(sub, "Sign payload transition error: "+err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}

		//domainWithoutScheme := strings.TrimPrefix(strings.TrimPrefix(sub.Domain, "https://"), "http://")
		//confirmationEmail := strings.ToLower("info@" + domainWithoutScheme)
		confirmationDate := time.Now().Format(time.RFC3339)
		canonicalPayload := CanonicalPayload{
			Domain:    sub.Domain,
			Action:    sub.WebcatAction,
			Signers:   sub.SigstoreSigners,
			Threshold: sub.SigstoreThreshold,
			//ConfirmationEmail: confirmationEmail,
			ConfirmationDate: confirmationDate,
		}
		payloadBytes, err := json.Marshal(canonicalPayload)
		if err != nil {
			AppendLog(sub, "Error marshaling canonical payload: "+err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}
		sub.Payload = string(payloadBytes)
		// Sign the payload (e.g. signing the hash of the canonical payload)
		hash := crypto.HashBytes(payloadBytes)

		signature, err := types.SignLeafMessage(signer, hash[:])
		if err != nil {
			AppendLog(sub, "Error signing payload: "+err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}
		sub.Signature = hex.EncodeToString(signature[:])
		sub.Hash = hex.EncodeToString(hash[:])

		updateState(StatePayloadSigned)
		AppendLog(sub, "Payload signed and saved")
	}
	// --- Step 7: Submit Signature to Sigsum ---
	if sub.Status == StatePayloadSigned {
		if err := machine.Event("submitSigsum"); err != nil {
			AppendLog(sub, "Submit sigsum transition error: "+err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}

		updateState(StateSigsumSubmitted)

		config := submit.Config{
			Policy:        &policy,
			PerLogTimeout: 300 * time.Second,
			// Domain rate limit stuuf should eventually go here
		}

		var message, errmsg = crypto.HashFromHex(sub.Hash)
		var signature, errsig = crypto.SignatureFromHex(sub.Signature)

		if errmsg != nil || errsig != nil {
			AppendLog(sub, "Error loading signature or hash from database: "+errmsg.Error()+errsig.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}

		publicKey := signer.Public()

		leaf := requests.Leaf{
			Message:   message,
			Signature: signature,
			PublicKey: publicKey,
		}

		ctx := context.Background()

		proof, err := submit.SubmitLeafRequest(ctx, &config, &leaf)
		AppendLog(sub, "Signature submitted to sigsum; waiting for inclusion proof")

		if err != nil {
			AppendLog(sub, "Failed to submit to log: "+err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}

		// TODO update list
		AppendLog(sub, "Inclusion proof received; verifying it...")

		prooferr := proof.Verify(&message, map[crypto.Hash]crypto.PublicKey{crypto.HashBytes(publicKey[:]): publicKey}, &policy)

		if prooferr != nil {
			AppendLog(sub, "Failed to verify received proof from the log: "+err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}

		AppendLog(sub, "Inclusion proof verified, completing transaction.")

		if err := machine.Event("complete"); err != nil {
			AppendLog(sub, "Complete transition error: "+err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}

		// --- Create Transparency Record ---
		var asciiproof bytes.Buffer
		proof.ToASCII(&asciiproof)
		record := TransparencyRecord{
			ID:           uuid.New().String(),
			SubmissionID: sub.ID,
			Hash:         sub.Hash,
			Payload:      sub.Payload,
			Signature:    sub.Signature,
			Proof:        asciiproof.String(),
			CreatedAt:    time.Now(),
		}

		// We must never lose data. If we happen to log something, and not be able to reproduce it,
		// then the whole integrity chain is broken...
		if err := DB.Create(&record).Error; err != nil {
			AppendLog(sub, "Error creating transparency record: "+err.Error())
		} else {
			AppendLog(sub, "Transparency record created with hash")
		}

		var listEntry ListEntry
		if sub.WebcatAction == "add" {
			// Create new list entry.
			listEntry = ListEntry{
				Domain:           sub.Domain,
				Signers:          sub.SigstoreSigners,
				Threshold:        sub.SigstoreThreshold, // obtained earlier
				TransparencyHash: sub.Hash,
				UpdatedAt:        time.Now(),
			}
			if err := DB.Create(&listEntry).Error; err != nil {
				AppendLog(sub, "Error creating list entry: "+err.Error())
				machine.Event("fail")
				updateState(machine.Current())
				return
			}
			AppendLog(sub, "List entry created for domain "+sub.Domain)
		} else if sub.WebcatAction == "delete" {
			if err := DB.Delete(&ListEntry{}, "domain = ?", sub.Domain).Error; err != nil {
				AppendLog(sub, "Error deleting list entry: "+err.Error())
				machine.Event("fail")
				updateState(machine.Current())
				return
			}
			AppendLog(sub, "List entry deleted for domain "+sub.Domain)
		} else if sub.WebcatAction == "modify" {
			if err != nil {
				AppendLog(sub, "Error: domain does not exist; cannot modify")
				machine.Event("fail")
				updateState(machine.Current())
				return
			}
			// Update existing list entry.
			listEntry.Signers = sub.SigstoreSigners
			listEntry.Threshold = sub.SigstoreThreshold
			listEntry.TransparencyHash = sub.Hash
			listEntry.UpdatedAt = time.Now()
			if err := DB.Save(&listEntry).Error; err != nil {
				AppendLog(sub, "Error updating list entry: "+err.Error())
				machine.Event("fail")
				updateState(machine.Current())
				return
			}
			AppendLog(sub, "List entry updated for domain "+sub.Domain)
		}

		updateState(machine.Current())

		if err := machine.Event("complete"); err != nil {
			AppendLog(sub, "Complete transition error: "+err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}
	}
}
