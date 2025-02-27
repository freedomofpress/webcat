# List Builder and Sigsum Submission Tool Documentation

This tool is designed to build a reproducible preload trust list independently of the list server. It works by scanning a public Sigsum log for leaves that match a given public key, then fetching the corresponding leaf source from the [API server](../list_server/API.md).

- If a leaf is present in the Sigsum log, but is missing from the API server, then something is wrong.
- The final state of the list is fully reproducible and deterministic. The inclusion order of leaves is preserved, meaning that anyone can run the tool at any point in time and obtain the exact same list, provided that the underlying log remains unchanged.
- The tool verifies each payload by reconstructing the canonical payload, computing its hash, and comparing it to the provided hash. It also confirms the signature on the payload, ensuring that any tampering is detected.

## How It Works

1. **Sigsum Log Scanning:**  
   - Connects to a specified public Sigsum log using its URL and log key.
   - Retrieves the tree head and processes leaves in batches.
   - Filters leaves by comparing their key hash with the target public key.

2. **API Server Leaf Retrieval:**  
   - For each matching leaf, constructs a URL to query the API server for the full transparency entry.
   - If a leaf present in the log is missing from the API server, the process halts with an error, indicating a security issue.

3. **Payload and Signature Verification:**  
   - Reconstructs the canonical payload from the transparency entry.
   - Computes and verifies the payload hash and signature.
   - Confirms the signature provided by the log verifies the API payload.

4. **List Construction:**  
   - Processes domain records based on their action (e.g., add or delete), sequentially based on log inclusion order.
   - Builds a binary blob by concatenating the SHA256 hash of each domain with its corresponding policy hash.

5. **List Signing and Proof Submission:**  
   - Computes an overall hash of the list and signs it.
   - Writes the signed list to a binary file and exports a JSON proof of submission.
   - Creates a symlink (`update.json`) pointing to the latest proof file.

## Reproducibility and Determinism
Anyone can run the tool, scan the same public Sigsum log, and fetch the corresponding leaves from the API server. As long as the log remains unchanged, the resulting list build will be identical, providing full transparency. It is possible to also reconstruct previous list updates, by changing the build tool to stop at a earlier tree size, as reported in the metadata of the updates that needs to be audited.

## Usage Example

```bash
go run main.go \
  -log-url "YOUR_SIGSUM_LOG_URL" \
  -log-key "YOUR_LOG_KEY_HEX" \
  -submit-key "YOUR_SUBMIT_KEY_HEX" \
  -data-server "https://transparency.cat/api" \
  -start-index 0 \
  -batch-size 512 \
  -output-dir "pub" \
  -signing-key-file "signing.key" \
  -policy "sigsum.policy.test"
```

## Artifacts

1. **Binary List File (`<hash>.bin`):**
   - Contains the concatenated binary blob of domain hashes and their corresponding policy hashes.
   - The filename is the overall SHA256 hash of the binary blob (e.g., `a1b2c3d4...bin`).
   - This file is the definitive artifact representing the current state of the list update.
   - It can be found on the server under a path like `<hash>.bin` for audit purposes.

2. **JSON Proof File:**
   - Contains the Sigsum proof of submission along with the original leaf hash.
   - The JSON proof provides detailed cryptographic evidence that the list was built from the approved leaves and signed using the designated signing key.
   - The JSON file is named using the overall list hash (e.g., `a1b2c3d4....json`).

3. **Symlink (`update.json`):**
   - A symlink is maintained to point to the most recent JSON proof file.
   - This symlink is updated with every new list update.
   - While the symlink always points to the latest artifact, all historical files are preserved in the repository for auditing.
   - This is what is fetched by the extensions to check if an update exists, and in case verify and download it.

For further details on the security model, update architecture, and overall system design, please refer to [../Readme.md](../Readme.md).