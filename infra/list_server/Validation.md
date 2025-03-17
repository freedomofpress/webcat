# WEBCAT Validation Process

The validation process in Webcat is implemented as a finite state machine (FSM) that performs certain validation steps  before enrollment of a domain into the preload trust list. The process, defined in the `ProcessSubmissionFSM` function, consists of several sequential steps:

TODO: Currently only the final payload is logged. Instead, for the _cool down_ period to be effective, a payload must be submitted at the beginning of the process, and one at the end of the waiting period. So that if an admin detects an anomaly, they have time to restore their servers or domains in a way that will fail the re-check.

1. **DNS Check (StateIngested → StateDNSChecked):**
   - The submitted domain is first validated for proper format.
   - A DNS lookup is performed to ensure that the domain resolves to at least one IP address.
   - On success, the FSM advances; on failure, the submission transitions to a `failed` state.

2. **HTTPS and Header Validation (StateDNSChecked → StateHeadersValid):**
   - An HTTPS request is made to the domain.
   - The response headers are validated to ensure they include the required Sigstore headers:
     - `x-webcat-action`: Specifies the intended action (e.g., `add`, `delete`, or `modify`).
     - `x-sigstore-threshold`: A numeric threshold for signature validation.
     - `x-sigstore-signers`: A normalized list of signers (containing `identity` and `issuer` fields).
   - The precise header format is detailed in the admin guide.
   - Successful header validation leads to the next state; any errors result in a failure.

3. **List Database Check (StateHeadersValid → StateListChecked):**
   - The preload trust list is checked to confirm whether the domain is eligible for the requested action.
   - For an "add" action, the domain must not already exist in the list.
   - For "delete" or "modify" actions, the domain must already be present.
   - Any discrepancy results in transitioning to the `failed` state.

4. **Validation Token and Waiting Period (StateListChecked → StateAwaitingConfirmation):**
The mode is selected by the preload list server config, not by the submitter. Email will probably not end up being in use.

   - Based on the confirmation mode:
     - **Email Mode:** A unique validation token is generated, hashed, and ideally sent via email (with a waiting period of 12 hours). *Note: Email validation is not currently in use, as it is not viable for onion services.*
     - **Cool-down Mode:** A waiting period is set to allow for a re-check of HTTPS headers. In the demo setup, this period is intentionally short (e.g., 1 minute). In production, it should be extended (e.g., to a week) to mitigate rapid changes (e.g. due to a domain takeover, or webserver compromise, or to spam the list).
   - The submission remains in the awaiting confirmation state until confirmation is received or the waiting period expires.

5. **Auto-Confirmation (StateAwaitingConfirmation):**
   - In recheck mode, once the waiting period expires, the system re-fetches the HTTPS headers.
   - If the new headers match the originally validated values, the submission is automatically confirmed.
   - Any discrepancies during this re-check cause the submission to fail.

6. **Payload Signing (StateConfirmed → StatePayloadSigned):**
   - After confirmation, a canonical payload is constructed that includes the domain, action, signers, threshold, and a confirmation date (in RFC3339 format).
   - This payload is serialized to JSON, hashed, and then signed using a cryptographic signer.
   - The resulting hash and signature are stored with the submission.

7. **Sigsum Submission (StatePayloadSigned → StateSigsumSubmitted):**
   - The signed payload is submitted to a Sigsum log.
   - The system awaits an inclusion proof, which is then verified against the submitted payload.
   - On successful verification, the process continues; otherwise, the submission fails.

8. **Completion (StateSigsumSubmitted → StateCompleted):**
   - A transparency record is created, linking the submission details, payload, signature, and the inclusion proof.
   - The FSM then marks the submission as completed.
   - Any errors encountered during these steps transition the submission to the `failed` state.

