# Web-based Code Assurance and Transparency (WEBCAT)
![webcat logo dark](./docs/icons/dark/256/webcat.png#gh-dark-mode-only)
![webcat logo light](./docs/icons/light/256/webcat.png#gh-light-mode-only)

The purpose of this project is to showcase an architectural framework that provides blocking code signing, as well as integrity and transparency checks for browser-based single-page applications. In doing so, it primarily leverages existing technologies and community infrastructure, including [Sigstore](https://sigstore.dev), [Sigsum](https://sigsum.org), and [The Update Framework](https://theupdateframework.io/). The browser extension has no runtime dependencies, and all cryptographic operations are performed using only the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). Runtime policy enforcement in the enrolled domains is handled by the browser's [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP).

The project has been written as a master's thesis for the [Master Computer Security at the Vrije Universiteit Amsterdam](https://vu.nl/csec) and the [University of Amsterdam](https://uva.nl), sponsored by the [Freedom of the Press Foundation](https://freedom.press). The full dissertation will appear later in this repository.

Webcat is:
 1. [An enrollment server](./infra/list_server/)
 2. [An updater service](./infra/build_server/)
 3. [A Firefox (v2) extension](./extension/)
 4. [A signing script](./tools/signing/)

See [The long and winding road to safe browser-based cryptography](https://securedrop.org/news/browser-based-cryptography/) for additional context.

See [apps](./apps) for a list of supported and in-progress apps.

See [threat model](./docs/ThreatModel.md) for preliminary threat model considerations.

If you are a developer and want to design or port your application, look at the [developer reference](./docs/DeveloperGuide.md) and also at the issues mentioning the porting of existing apps (such as: https://github.com/freedomofpress/webcat/issues/28, https://github.com/freedomofpress/webcat/issues/26, https://github.com/freedomofpress/webcat/issues/25).

## Web Features Support Matrix

| Feature             | Supported? | CSP Directive / Value         | Notes                                          |
|---------------------|------------|-------------------------------|------------------------------------------------|
| WebAssembly         | Yes        | script-src 'wasm-unsafe-eval' |   |
| Web Workers   | Yes        | worker-src 'self'                   |            |
| Shared Workers      | Yes        | worker-src 'self'               |                                |
| Service Workers     | Yes        | worker-src 'self'                   |                              |
| Iframes             | Yes        | frame-src/child-src  'self' blob: data: <enrolled_origin>                   | External origins needs to be enrolled.                |
| Nested Iframes      | Yes        | frame-src/child-src  'self' blob: data: <enrolled_origin>                  |  All external origins needs to be enrolled.   |
| Inline Script       | No         | ~~script-src 'unsafe-inline'~~  |                  |
| Script Hash         | No         | ~~script-src sha256-xxx~~      |                |
| Script Unsafe Eval  | No         | ~~script-src 'unsafe-eval'~~    |                     |

It is implemented and theoretically possible to include scripts from remote origins that are also enrolled (and similarly workers or styles), still providing a transparency chain of all hosts and allowing loads from CDNs. This is because origin validation is recursive, and enrollment is checked when the manifest is parsed and validated.

## Testing Applications
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

![Diagram depicting the full architecture, as described below](./docs/architecture.svg)

The following points describe how the signing, enrollment, and subsequent validation happen at a high level.

### 1. App Developer(s)

  1. The developer builds an application manifest that lists all web application files (e.g., `script.js`, HTML files, web workers, and WebAssembly snippets) along with their hashes. The manifest also defines the expected Content Security Policy (CSP) for each application path (and a fallback one). This allows an application to specify different CSPs for scenarios such as sandboxing (e.g., via iframes) or granting different permissions to workers.
  2. The manifest is signed using Sigstore. The developer authenticates via OIDC to obtain a short-lived certificate from Sigstore's Fulcio, and that certificate is logged in Rekor. The certificate, which includes the issuer details, is used to sign the manifest.
  3. If necessary, more developers add their signature, since multiple identities can sign a manifest, and each signing event is transparently logged in the Fulcio transparency log. Each signature is logged in Rekor.

### 2. Website Administrator

  1. The website administrator who wants to enroll in the preload mechanism adds specific HTTP headers that:
    - Declare the intent to participate in the service.
    - Specify which identities (and their issuers) are authorized to sign for the domain.
    - Define a signing threshold—indicating how many valid signatures are required for the manifest to be considered valid.
  2. Sends their domain to the enrollment service.
  3. Deploys the signed web application.
  
_Note on trust decisions (administrators that are also developers)_:
  - If the application is open source and maintained by trusted parties, the administrator might choose to trust the maintainers' signatures.
  - If the administrator modifies or builds a custom version, they must sign the application with their own OIDC identity and thus use those in the headers.

### 3. Webcat Services Operator

#### Enrollment Server
  1. Receive domain submissions from anyone on the internet.
  2. Verifies that the domain is not already enrolled, checks the HTTP headers, computes a hash based on signers and threshold, and submits a signed payload to the Sigsum transparency log.
  3. Waits a _cool down_ period (e.g.: a week), and performs the checks and the payload signing and inclusion again (same as point 2, but with an updated timestamp).

#### Build Server and Update Server
  4. An asynchronous list building service (running periodically, such as daily) collects signed proofs from the Sigsum log and fetches original payloads from the enrollment service.
  5. It reproducibly builds a preload trust list that preserves the inclusion order of entries.
  6. The new list is signed using a dedicated list update key, and the signing event is logged in Sigsum.
  7. Publish a metadata file describing the most recent list version to the update server.

  _Note_: Historical files are preserved for audit purposes, allowing anyone to verify the signing key and list updates.

### 4. User Browser

- Extension initialization and update (at install and startup, or if a long running browser instance every 24 hours):

    1. At startup, the browser extension fetches Sigstore trust updates via The Update Framework (TUF).
    2. It also checks for list updates. When a new signed list is available, the extension verifies its signature and inclusion proof using the signed tree head to guard against rollbacks.

- Runtime integrity checks (running at every page load):

    3. When a user opens a new main frame (e.g., a new tab), the extension performs a local lookup to determine if the domain is enrolled.
    4. If enrolled, it verifies that the header hash (reflecting signers and threshold) matches the one stored in the list.
    5. The extension then fetches the manifest from the same origin and validates the Sigstore signatures, ensuring that at least the required threshold of valid signatures is present.
    6. Every executable asset (scripts, HTML, WebAssembly, workers) is integrity-checked against the hashes specified in the manifest at the network level.
    7. If all checks pass, a green icon is displayed along with verification details (such as signing identities and loaded assets). If any integrity check fails, execution is halted and the user is redirected to a blocking page before any compromised material reaches the DOM.

### 5. Auditors
The system is fully transparent and auditable. Different parties can be interested in auditing only those relevant to them: a developer can monitor the usage of their OIDC identity, while a website administrator can monitor any list changes that affect their domain(s).

- **Audit List Changes:** By tracking signing events in the Sigsum transparency log, auditors can observe every change made to the list. See the [Sigsum getting started documentation](https://www.sigsum.org/getting-started/) for a walkthrough on how. With the _cool down_ period, administrators can monitor when a change is requested, but detect it before it is merged, and if it is malicious, revert it before the next enrollment server check.

- **Audit Distributed List Blobs:** Auditors can reproducibly rebuild the preload trust list from the enrollment data and compare it with the distributed blobs. This ensures that the distributed list is identical to the one generated from the source data. Additionally, all signing events of the list builder are logged, allowing auditors to review every update. The update server should maintain all historical data, so that all the signing events in the Sigsum log are reproducible.

- **Audit OIDC Certificate Issuance:** By examining the Rekor transparency log, auditors (and developers) can track the issuance of OIDC certificates. This helps confirm that certificate issuance is done transparently and according to policy. See the Rekor web interface](https://search.sigstore.dev/) to search through the issued certificates.

- **Audit Artifact Signing:** Auditors can also verify that artifacts are signed correctly by monitoring the artifacts signatures logged by Rekor. Developers should keep public an archive of all the artifacts they ever signed with a given identit.

## Acknowledgements
Thanks to [smaury](https://github.com/smaury) of [Shielder](https://www.shielder.com/) and to [antisnatchor](https://github.com/antisnatchor) of [Persistent Security](https://www.persistent-security.net/) for their security-related insights. Thanks to [Giorgio Maone](https://github.com/hackademix) of the Tor Project for the development-related support.