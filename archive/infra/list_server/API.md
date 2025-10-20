# WEBCAT List API

The List API manages domain enrollments into a preload trust list. It provides endpoints for domain submission, status checking, transparency record retrieval, and domain confirmation. Detailed information on the domain verification process is provided in a separate documentation file, see [Validation.md](./Validation.md).

Depending on the configuration, email confirmation may be required. If email confirmation is disabled, a waiting period is enforced to prevent rapid changes due to DNS updates or potential domain takeovers.

## Endpoints

### POST `/submit`
- **Description:**  
  Submits a domain for enrollment. Before creating a new submission, the API checks whether an active (non-finalized) submission for the same domain already exists.
  
- **Request:**
  ```json
  {
    "domain": "example.com"
  }
  ```

- **Response:**
  ```json
  {
    "uid": "generated-uuid",
    "message": "Domain submitted successfully"
  }
  ```

### GET `/status/:uid`
- **Description:**  
  Retrieves the current status and log entries for a submission identified by its UID. Return both status logs and error logs in case of failures.
  
- **Response:**
  ```json
  {
    "domain": "example.com",
    "status": "current status",
    "logs": [
      {
        "message": "Submission confirmed via confirmation link",
        "timestamp": "2025-02-27T15:04:05Z"
      }
    ]
  }
  ```

### GET `/transparency/:hash`
- **Description:**  
  Retrieves a transparency record for a given hash.
  
- **Response:**
  ```json
  {
    "hash": "record-hash",
    "payload": "payload-data",
    "signature": "signature-data",
    "proof": "proof-data",
    "createdAt": "2025-02-27T15:04:05Z"
  }
  ```

### POST `/confirm/:uid`
- **Description:**  
  Confirms a domain submission using a confirmation code. The API computes the SHA256 hash of the provided code and compares it with the stored validation token. Confirmation only succeeds if the submission is in the proper state and within the allowed waiting period.
  
- **Request:**
  ```json
  {
    "code": "the-raw-confirmation-code"
  }
  ```

- **Response:**
  ```json
  {
    "message": "Submission confirmed"
  }
  ```

## Possible Submission Statuses

- `ingested` (StateIngested): The domain has been ingested.
- `dns_checked` (StateDNSChecked): The DNS records have been checked.
- `headers_valid` (StateHeadersValid): The HTTP headers are valid.
- `list_checked` (StateListChecked): The preload list has been checked.
- `awaiting_confirmation` (StateAwaitingConfirmation): Awaiting confirmation code.
- `confirmed` (StateConfirmed): The domain has been confirmed.
- `payload_signed` (StatePayloadSigned): The payload has been signed.
- `sigsum_submitted` (StateSigsumSubmitted): Submitted to the sigsum process.
- `completed` (StateCompleted): The process is completed.
- `failed` (StateFailed): The submission failed.

See `common/fsm.go` to understand the checks happening at each phase.

## Email Confirmation & Waiting Period

Email confirmation is part of the domain verification process. Depending on the list configuration:
- **If email confirmation is enabled:** A confirmation email will be sent.
- **If disabled:** A waiting period is enforced to mitigate rapid changes due to DNS updates or domain takeovers.

## Database Initialization

The API initializes its database using the `DATABASE_PATH` environment variable.

## Running the API

Set the `DATABASE_PATH` environment variable and then run the API server:

```bash
export DATABASE_PATH=/path/to/your/database.db
go run main.go
```

## Verification Process Documentation

For a detailed explanation of the domain verification process, please refer to the separate documentation file included in the repository.

# Demo Setup for Webcat

This document describes the demo setup for the Webcat services, which includes two systemd units: `webcat-api.service` and `webcat-processor.service`. These services require a dedicated system user, proper folder structure, and appropriate file permissions.

## Systemd Units

### Webcat API Service

Create the file `/etc/systemd/system/webcat-api.service` with the following contents:

```ini
[Unit]
Description=Webcat API Service
After=network.target

[Service]
Type=simple
User=webcat
Environment="GIN_MODE=release"
Environment="DATABASE_PATH=/var/webcat/"
WorkingDirectory=/var/webcat/
ExecStart=/usr/bin/webcat-api
Restart=on-failure
RestartSec=5
StandardOutput=append:/var/webcat/logs/api.log
StandardError=append:/var/webcat/logs/api.log

[Install]
WantedBy=multi-user.target
```

### Webcat Processor Service

Create the file `/etc/systemd/system/webcat-processor.service` with the following contents:

```ini
[Unit]
Description=Webcat Processor Service
After=network.target

[Service]
Type=simple
User=webcat
Environment="DATABASE_PATH=/var/webcat/"
Environment="SIGSUM_LOG_POLICY_PATH=/etc/webcat/sigsum.policy"
Environment="SIGSUM_PRIVATE_KEY_PATH=/var/webcat/keys/list-signing.key"
WorkingDirectory=/var/webcat/
ExecStart=/usr/bin/webcat-processor
Restart=on-failure
RestartSec=5
StandardOutput=append:/var/webcat/logs/processor.log
StandardError=append:/var/webcat/logs/processor.log

[Install]
WantedBy=multi-user.target
```

## User and Folder Setup

1. **Create the `webcat` User:**

   Ensure the dedicated `webcat` user exists to run the services:
   ```bash
   sudo useradd -r -s /usr/sbin/nologin webcat
   ```

2. **Set Up the Directory Structure:**

   - **Application Directory:**  
     Create `/var/webcat` and its subdirectories. This directory must be owned by the `webcat` user.
     ```bash
     sudo mkdir -p /var/webcat/logs /var/webcat/keys
     sudo chown -R webcat:webcat /var/webcat
     ```

   - **Configuration Directory:**  
     Create `/etc/webcat` for configuration files. This directory should be owned by `root`.
     ```bash
     sudo mkdir -p /etc/webcat
     sudo chown -R root:root /etc/webcat
     ```

3. **Sigsum Policy File:**

   A [Sigsum policy](https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/doc/policy.md) must be provided at `/etc/webcat/sigsum.policy`. Create and populate this file as required for your deployment.

## Enabling and Starting the Services

After creating the systemd unit files and setting up the necessary users and directories, reload systemd and enable/start the services:

```bash
sudo systemctl daemon-reload
sudo systemctl enable webcat-api.service
sudo systemctl enable webcat-processor.service
sudo systemctl start webcat-api.service
sudo systemctl start webcat-processor.service
```

Monitor the logs in `/var/webcat/logs` to ensure that the services are running correctly. The API will be listrning on `127.0.0.1:8080`, so a reverse proxy like nginx is be needed for TLS support.

See the following sample nginx virtual host:

```
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 301 https://transparency.cat$request_uri;
}


server {
	listen 443 ssl http2 default_server;
	listen [::]:443 ssl http2 default_server;
	server_name transparency.cat;

	location / {
		try_files $uri $uri/ =404;
	}

	ssl_certificate /etc/letsencrypt/live/transparency.cat/fullchain.pem;
	ssl_certificate_key /etc/letsencrypt/live/transparency.cat/privkey.pem;
	include /etc/letsencrypt/options-ssl-nginx.conf;
	ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

	add_header X-Content-Type-Options nosniff always;
	add_header X-Frame-Options "deny" always;
	add_header X-XSS-Protection "1; mode=block" always;
	add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
	add_header Content-Security-Policy "default-src 'none'; script-src 'self'; style-src 'self';" always;

	root /var/www/html;
	index index.html;

	location = / {
		try_files /index.html =404;
	}

	location /api/ {
        	proxy_pass http://127.0.0.1:8080/;
        	proxy_set_header Host $host;
        	proxy_set_header X-Real-IP $remote_addr;
	}

	location /update/ {
		alias /var/webcat-builder/pub/;
		autoindex on;
	}

}
```