package common

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/looplab/fsm"
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
	Action            string   `json:"action"`             // e.g., "add", "modify", or "delete" (lowercase)
	Signers           []Signer `json:"signers"`            // a slice of signer objects, each with only identity and issuer
	Threshold         int      `json:"threshold"`          // integer from x-sigstore-threshold
	ConfirmationEmail string   `json:"confirmation_email"` // e.g., "info@example.com"
	ConfirmationDate  string   `json:"confirmation_date"`  // RFC3339 format date
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

func ProcessSubmissionFSM(sub *Submission, signer crypto.Signer, policy policy.Policy) {
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
		hostname := strings.TrimPrefix(strings.TrimPrefix(sub.Domain, "https://"), "http://")
		ips, err := net.LookupIP(hostname)
		if err != nil || len(ips) == 0 {
			AppendLog(sub, "DNS lookup failed")
			machine.Event("fail")
			updateState(machine.Current())
			return
		}
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
		// Validate required headers:
		if respHeaders.Get("x-sigstore-signers") == "" {
			AppendLog(sub, "Missing required header: x-sigstore-signers")
			machine.Event("fail")
			updateState(machine.Current())
			return
		}
		if respHeaders.Get("x-sigstore-threshold") == "" {
			AppendLog(sub, "Missing required header: x-sigstore-threshold")
			machine.Event("fail")
			updateState(machine.Current())
			return
		}
		webcatAction := respHeaders.Get("x-webcat-action")
		if webcatAction == "" {
			AppendLog(sub, "Missing required header: x-webcat-action")
			machine.Event("fail")
			updateState(machine.Current())
			return
		}
		webcatAction = strings.ToUpper(webcatAction)
		if webcatAction != "ADD" && webcatAction != "MODIFY" && webcatAction != "DELETE" {
			AppendLog(sub, "Invalid x-webcat-action value: must be ADD, MODIFY, or DELETE")
			machine.Event("fail")
			updateState(machine.Current())
			return
		}
		// Validate the sigstore headers (additional format checks).
		if err := validateSigstoreHeaders(respHeaders); err != nil {
			AppendLog(sub, "Header validation failed: "+err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}
		AppendLog(sub, "HTTPS check and header validation successful")
		// Persist the critical header values.
		sub.SigstoreSigners = respHeaders.Get("x-sigstore-signers")
		sub.SigstoreThreshold = respHeaders.Get("x-sigstore-threshold")
		sub.WebcatAction = respHeaders.Get("x-webcat-action")
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
		// (In production, perform a lookup against your separate list database.)
		AppendLog(sub, "List database check passed")
		updateState(machine.Current())
	}

	// --- Step 5: Send Validation Email ---
	if sub.Status == StateListChecked {
		if err = machine.Event("sendValidation"); err != nil {
			AppendLog(sub, "Send validation transition error: "+err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}
		// Generate a raw confirmation code.
		rawToken := uuid.New().String()
		// Compute the SHA-256 hash of the raw token.
		fmt.Println(rawToken)
		hashedToken := ComputeSHA256(rawToken)
		// Store only the hashed token.
		sub.ValidationToken = hashedToken
		// Set the wait deadline to 12 hours from now.
		waitUntil := time.Now().Add(12 * time.Hour)
		sub.WaitUntil = &waitUntil
		// Log a generic message (do not include the raw token).
		AppendLog(sub, "Validation email sent; waiting for confirmation until "+waitUntil.Format(time.RFC3339))
		updateState(machine.Current())
		// (In production, email the rawToken to the user externally.)
		return
	}

	// --- Step 5b: Awaiting Confirmation ---
	if sub.Status == StateAwaitingConfirmation {
		// If still waiting, do not proceed.
		if sub.WaitUntil != nil && time.Now().Before(*sub.WaitUntil) {
			AppendLog(sub, "Still waiting for confirmation; will re-check later")
			return
		}
		// If the wait has expired and no confirmation was received, mark as failed.
		if sub.Status == StateAwaitingConfirmation {
			AppendLog(sub, "Waiting period expired without confirmation")
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
		// Build canonical payload from persisted header values.
		action := strings.ToLower(sub.WebcatAction)
		var parsedSigners []Signer
		if err := json.Unmarshal([]byte(sub.SigstoreSigners), &parsedSigners); err != nil {
			AppendLog(sub, "Error parsing persisted signers: "+err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}
		threshold, err := strconv.Atoi(sub.SigstoreThreshold)
		if err != nil {
			AppendLog(sub, "Error parsing persisted threshold: "+err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}
		domainWithoutScheme := strings.TrimPrefix(strings.TrimPrefix(sub.Domain, "https://"), "http://")
		confirmationEmail := strings.ToLower("info@" + domainWithoutScheme)
		confirmationDate := time.Now().Format(time.RFC3339)
		canonicalPayload := CanonicalPayload{
			Action:            action,
			Signers:           parsedSigners,
			Threshold:         threshold,
			ConfirmationEmail: confirmationEmail,
			ConfirmationDate:  confirmationDate,
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

		leaf := requests.Leaf{
			Message:   message,
			Signature: signature,
			PublicKey: signer.Public(),
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

		// TODO sigsum-verify proof before completing and then updating the list
		// TODO update list

		if err := machine.Event("complete"); err != nil {
			AppendLog(sub, "Complete transition error: "+err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}
		AppendLog(sub, "Inclusion proof received; submission completed")

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

		updateState(machine.Current())

		if err := machine.Event("complete"); err != nil {
			AppendLog(sub, "Complete transition error: "+err.Error())
			machine.Event("fail")
			updateState(machine.Current())
			return
		}
	}
}
