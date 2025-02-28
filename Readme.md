# Web-based Code Assurance & Transparency (WEBCAT)
![webcat logo dark](./docs/icons/dark/256/webcat.png#gh-dark-mode-only)
![webcat logo light](./docs/icons/light/256/webcat.png#gh-light-mode-only)

The purpose of this project is to showcase an architectural framework that provides blocking code signing, as well as integrity and transparency checks for browser-based single-page applications. In doing so, it primarily leverages existing technologies and community infrastructure, including [Sigstore](https://sigstore.dev), [Sigsum](https://sigsum.org), and [The Update Framework](https://theupdateframework.io/). The browser extension has no runtime dependencies, and all cryptographic operations are performed using only the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). Runtime policy enforcement in the enrolled domains is handled by the browser's [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP).

The project has been written as master thesis for the [Master Computer Security at the Vrije Universiteit Amsterdam](vu.nl/csec) and the [University of Amsterdam](https://uva.nl), sponsored by the [Freedom of the Press Foundation](https://freedom.press). The full dissertation will appear later in this repository.

Webcat is:
 1. [An enrollment server](./infra/list_server/)
 2. [An updater service](./infra/build_server/)
 3. [A Firefox (v2) extension](./extension/)
 4. [A signing script](./tools/signing/)

See [The long and winding road to safe browser-based cryptography](https://securedrop.org/news/browser-based-cryptography/) for additional context.

See [apps](./apps) for a list of supported and in-progress apps.

See [threat model](./docs/ThreatModel.md) for preliminary threat model considerations.

If you are a developer and want to design or port your application, look at the [developer reference](./docs/DeveloperGuide.md) and also at the issues mentioning the porting of existing apps (such as: https://github.com/freedomofpress/webcat/issues/28, https://github.com/freedomofpress/webcat/issues/26, https://github.com/freedomofpress/webcat/issues/25).

## Alpha
The unsigned extension, to use exclusively for testing, development, and debugging, is built via GitHub Actions at every commit. [Download the artifact from the latest run](https://github.com/freedomofpress/webcat/actions/workflows/build-extension.yml). Once unzipped, it can be installed temporarily in Firefox via `about:debugging#/runtime/this-firefox` and then choosing _"Load Temporary Add-on..."_ and selecting the extracted `manifest.json`.

The following test domains are provided solely for demonstration and showcasing purposes. As such, they are **not secure**, **not well-maintained**, and do not guarantee any form of **data retention**. A test enrollment server and list distributor—provided without any guarantees—are available at `https://transparency.cat/api/` and `https://transparency.cat/update/`.


| **Domain**                                      | **App**                                                                                     | **Description**                                       |
|-------------------------------------------------|---------------------------------------------------------------------------------------------|-------------------------------------------------------|
| [testapp.nym.re](https://testapp.nym.re)       | [**Testapp**](https://github.com/freedomofpress/webcat/tree/main/apps/testapp)              | Showcases WASM, Webworkers, Workers, and Sharedworkers support. |
| [element.nym.re](https://element.nym.re)       | [**Element**](https://github.com/element-hq/element-web)                                   | The Matrix client.                                   |
| [globaleaks.nym.re](https://globaleaks.nym.re) | [**Globaleaks**](https://github.com/globaleaks/globaleaks-whistleblowing-software)         | Whistleblowing platform.                             |
| [jitsi.nym.re](https://jitsi.nym.re)           | [**Jitsi Meet**](https://github.com/jitsi/jitsi-meet)                                      | Video conferencing software.                         |
| [standardnotes.nym.re](https://standardnotes.nym.re) | [**Standard Notes**](https://github.com/standardnotes/app)                                | A secure and private notes app.                     |
| [bitwarden.nym.re](https://bitwarden.nym.re)   | [**Bitwarden**](https://github.com/bitwarden/clients)                                      | Cloud password manager.                              |
| [cryptpad.nym.re](https://cryptpad.nym.re)     | [**CryptPad**](https://github.com/cryptpad/cryptpad)                                       | End-to-end encrypted collaboration suite.            |


![Screenshot of Jitsi validation](https://github.com/user-attachments/assets/82c2bd63-f062-4d30-8b5d-b6a589120ba6)



## Architectural Overview
The following points describe how the signing, enrollment, and subsequent validation happen at a high level.

### 1. App Developer

  - The developer creates an application manifest that lists all web application files (e.g., `script.js`, HTML files, web workers, and WebAssembly snippets) along with their hashes.
  - The manifest also defines the expected Content Security Policy (CSP) for each application path (and a fallback one). This allows an application to specify different CSPs for scenarios such as sandboxing (e.g., via iframes) or granting special permissions to workers.
  - The manifest is signed using Sigstore. The developer authenticates via OIDC to obtain a short-lived certificate from the Sigstore Certificate Authority (CA) through Rekor.
  - The certificate, which includes the issuer details, is used to sign the manifest.
  - Multiple identities can sign a manifest, and each signing event is transparently logged in the Fulcio transparency log.

### 2. Website Administrator

  - The website administrator decides to enable the integrity protections offered by the system.
  - They must enroll their website by ensuring that the signed web application is served with the correct manifest and CSP.
  - The administrator adds specific HTTP headers that:
    - Declare the intent to participate in the service.
    - Specify which identities (and their issuers) are authorized to sign for the domain.
    - Define a signing threshold—indicating how many valid signatures are required for the manifest to be considered valid.
  
_Trust decisions (administrators that are also developers)_:
  - If the application is open source and maintained by trusted parties, the administrator might choose to trust the maintainers' signatures.
  - If the administrator modifies or builds a custom version, they must sign the application with their own OIDC identity and thus enroll those.

### 3. Webcat Sevices Operator

#### Enrollment Service
  - Once a website is ready (i.e., serving a signed web application with the correct manifest and CSP), the administrator submits the domain to an enrollment service.
  - The enrollment service verifies that the domain is not already enrolled, checks the HTTP headers, computes a hash based on signers and threshold, and sends a signed payload to the Sigstore transparency log.

#### List Building and Distribution
  - An asynchronous list building service (running periodically, such as daily) collects signed proofs from the Sigsum log and fetches original payloads from the enrollment service.
  - It reproducibly builds a preload trust list that preserves the inclusion order of entries.
  - The new list is signed using a dedicated list update key, and the signing event is logged in Sigsum.
  - Historical files are preserved for audit purposes, allowing anyone to verify the signing key and list updates.

### 4. User Browser

- **Extension Initialization and Updates:**
  - At startup, the browser extension fetches Sigstore trust updates via The Update Framework (TUF).
  - It also checks for list updates. When a new signed list is available, the extension verifies its signature and inclusion proof using the signed tree head to guard against rollbacks.

- **Runtime Integrity Checks:**
  - When a user opens a new main frame (e.g., a new tab), the extension performs a local lookup to determine if the domain is enrolled.
  - If enrolled, it verifies that the header hash (reflecting signers and threshold) matches the one stored in the list.
  - The extension then fetches the manifest from the same origin and validates the Sigstore signatures—ensuring that at least the required threshold of valid signatures is present.
  - Every executable asset (scripts, HTML, WebAssembly) is integrity-checked against the hashes specified in the manifest at the network level.
  - If all checks pass, a green icon is displayed along with verification details (such as signing identities and loaded assets). If any integrity check fails, execution is halted and the user is redirected to a blocking page before any compromised material reaches the DOM.

### 5. Auditors
The system is fully transparent and auditable. Different parts can be interested in auding only those relevant to them: a developer can monitor the usage of their OIDC identity, while a website administrator can monitor any list changes that affect their domain(s).

- **Monitor List Changes:** By tracking signing events in the Sigsum transparency log, auditors can observe every change made to the list. See the [Sigsum getting started documentation](https://www.sigsum.org/getting-started/) for a walkthrough on how.

- **Verify Distributed List Blobs:** Auditors can reproducibly rebuild the preload trust list from the enrollment data and compare it with the distributed blobs. This ensures that the distributed list is identical to the one generated from the source data. Additionally, all signing events of the list builder are logged, allowing auditors to review every update.

- **Monitor OIDC Certificate Issuance:** By examining the Fulcio transparency log, auditors can track the issuance of OIDC certificates. This helps confirm that certificate issuance is done transparently and according to policy. See the [Rekor web interface](https://search.sigstore.dev/) to search through the issued certificates.

- **Verify Artifact Signing:** Auditors can also verify that artifacts are signed correctly by monitoring the certificates issued by Fulcio. This ensures that the artifacts' signing events, as recorded by Fulcio, match the expected cryptographic proofs.
