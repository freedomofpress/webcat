# WEBCAT List Builder

A demo of the produced artifacts can be seen visiting [the test update server](https://transparency.cat/update/).

This tool is designed to build a reproducible preload trust list independently of the list server. It works by scanning a public Sigsum log for leaves that match a given public key, then fetching the corresponding leaf source from the [API server](../list_server/API.md).

- If a leaf is present in the Sigsum log, but is missing from the API server, then something is wrong.
- The final state of the list is fully reproducible and deterministic. The inclusion order of leaves is preserved, meaning that anyone can run the tool at any point in time and obtain the exact same list, provided that the underlying log remains unchanged.
- The tool verifies each payload by reconstructing the canonical payload, computing its hash, and comparing it to the provided hash. It also confirms the signature on the payload.

## How It Works

1. **Sigsum Log Scanning:**  
   - Connects to a specified public Sigsum log using its URL and log key.
   - Retrieves the tree head and processes leaves in batches.
   - Filters leaves by comparing their key hash with the target public key.

2. **API Server Leaf Retrieval:**  
   - For each matching leaf, constructs a URL to query the API server to retrieve the original payload that has been transparently logged, since Sigsum stores only a checksum.
   - If a leaf present in the log is missing from the API server, the process halts with an error.

3. **Payload and Signature Verification:**  
   - Computes and verifies the payload hash and signature.
   - Confirms the signature provided by the log verifies the API payload.

4. **List Construction:**  
   - Processes domain records based on their action (e.g., add or delete), sequentially based on log inclusion order.
   - Builds a binary blob by concatenating the SHA256 hash of each domain with the SHA256 of the corresponding policy (`x-sigstore-signers` and `x-sigstore-threshold`).

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
   - It should be archived on the update server under a path like `<hash>.bin` for audit purposes.

2. **JSON Proof File (`<hash>.json`):**
   - Contains the Sigsum proof of submission along with the original leaf hash.
   - The JSON proof provides detailed cryptographic evidence that the list was built from the approved leaves and signed using the designated signing key.
   - The JSON file is named using the overall list hash (e.g., `a1b2c3d4....json`).

3. **Symlink (`update.json`):**
   - A symlink is maintained to point to the most recent JSON proof file.
   - This is what is fetched by the extensions to check if an update exists, and in case verify and download it.

For further details on the security model, update architecture, and overall system design, please refer to [../Readme.md](../Readme.md).

## Systemd Service Configuration

Create the file `/etc/systemd/system/webcat-builder.service` with the following content:

```
[Unit]
Description=Webcat List Builder Service
After=network.target

[Service]
Type=oneshot
User=webcat-builder
WorkingDirectory=/var/webcat-builder
ExecStart=/usr/bin/webcat-builder -log-url="YOUR_SIGSUM_LOG_URL" -submit-key="YOUR_SUBMIT_KEY_HEX" -log-key="YOUR_LOG_KEY_HEX" -start-index=0 -batch-size=512 -data-server https://transparency.cat/api -policy /etc/webcat/sigsum.policy
StandardOutput=append:/var/webcat-builder/logs/list-builder.log
StandardError=append:/var/webcat-builder/logs/list-builder.log

[Install]
WantedBy=multi-user.target
```

## User and Folder Setup

1. Create the Service User:

   The service must run under a dedicated system user:
   ```bash
   sudo useradd -r -s /usr/sbin/nologin webcat-builder
   ```

2. Create the Working Directory:

   Create the working directory for the builder and ensure correct ownership:
   ```bash
   sudo mkdir -p /var/webcat-builder/logs
   sudo chown -R webcat-builder:webcat-builder /var/webcat-builder
   ```

3. Configuration Files:
   
   The Sigsum policy file should be located at `/etc/webcat/sigsum.policy`. Ensure the configuration directory exists and is owned by `root`:
   
   ```bash
   sudo mkdir -p /etc/webcat
   sudo chown -R root:root /etc/webcat
   ```
Place your Sigsum policy configuration in `/etc/webcat/sigsum.policy`.

## Webserver

A webserver is required to serve the output directory (commonly `/var/webcat-builder/pub/`) over TLS. Configure your preferred webserver (e.g., Nginx, Apache) with a valid TLS certificate to serve the `/pub/` directory. The correspnding public domain is configured at extension build time, in [config.ts](https://github.com/freedomofpress/webcat/blob/24948a8cd1730057569af78e238fc45eb0f1b678/extension/src/config.ts#L18).

## Enable and Run the Service

After configuring the service and preparing the environment, reload systemd and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl start webcat-builder.service
```

The builder will run once and log its output to `/var/webcat-builder/logs/list-builder.log`. Check this log for details on the list building process and any issues encountered. The generated public key used to sign the list updates must also be configured in the extension code before building, along the chosen log and witneses public key, aso in [config.ts](https://github.com/freedomofpress/webcat/blob/24948a8cd1730057569af78e238fc45eb0f1b678/extension/src/config.ts#L12).
