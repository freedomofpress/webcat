# Web-based Code Assurance and Transparency (WEBCAT)
![webcat logo dark](./docs/icons/dark/256/webcat.png#gh-dark-mode-only)
![webcat logo light](./docs/icons/light/256/webcat.png#gh-light-mode-only)

> [!IMPORTANT]
> Most of the documentation in the repository, including the dissertation, references a previous architecture, which is currently being reworked. Most information about web applications and manifests remains unchanged, while major parts of the infrastructure are deprecated. Target alpha release: December 2025.

> [!NOTE]
> To read the motivation for this project and the problem it solves, please [read our introductory blog post on WEBCAT](https://securedrop.org/news/introducing-webcat-web-based-code-assurance-and-transparency/).

The purpose of this project is to showcase an architectural framework that provides blocking code signing, as well as integrity and transparency checks for browser-based applications. In doing so, it primarily leverages existing technologies and community infrastructure, including [Sigsum](https://sigsum.org), and [CometBFT](https://github.com/cometbft/cometbft). The browser extension has no external runtime dependencies, and all cryptographic operations are performed using only the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). Runtime policy enforcement in the enrolled domains is handled by the browser's [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP).

The project has been originally written as a master's thesis for the [Master Computer Security at the Vrije Universiteit Amsterdam](https://vu.nl/csec) and the [University of Amsterdam](https://uva.nl), sponsored by the [Freedom of the Press Foundation](https://freedom.press). [The full dissertation is available on ePrint](https://eprint.iacr.org/2025/797.pdf). It has since evolved to address censorships risks, centralization, and single points of failure concerns.

WEBCAT is:
 1. [An enrollment consensus system](https://github.com/freedomofpress/webcat-infra-chain)
 2. [A set of specifications](https://github.com/freedomofpress/webcat-spec)
 3. [A Firefox (v2) extension](./extension/)
 4. [A CLI for developers and hosters](https://github.com/freedomofpress/webcat-cli)
 5. Some dependencies, such as [sigsum-ts](github.com/freedomofpress/sigsum-ts) and [cometbft-ts](https://github.com/freedomofpress/cometbft-ts). Though they are no longer in use in WEBCAT, we also worked on [tuf-browser](https://github.com/freedomofpress/tuf-browser) and [sigstore-browser](https://github.com/freedomofpress/sigstore-browser).

**This is currently experimental software and should not be used in production**.

See [The long and winding road to safe browser-based cryptography](https://securedrop.org/news/browser-based-cryptography/) and [Introducing WEBCAT](https://securedrop.org/news/introducing-webcat-web-based-code-assurance-and-transparency/) for additional context.

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


## Overview
![Diagram depicting the full architecture, as summarized below](./docs/architectureV2.svg)

[Click here for a PNG version.](./docs/architectureV2.png)

### Enrollment Consensus System

The enrollment system has three roles:
* Log all enrollment transactions
* Process enrollment transactions
* Build daily enrollment lists

This is a permissioned chain run by a limited set of trusted organizations. External parties can audit the chain but do not participate in consensus. The chain governs enrollment, modification, and de-enrollment. Nodes (and validators) independently fetch the target host, observe the proposed change, and agree on both the observed state and the operation's validity (e.g., you cannot de-enroll a domain that isn’t currently enrolled).

Once per day, the chain initiates a list-building transaction that deterministically applies the full history to produce the current enrollment list. That list is distributed to users' browsers at startup and at predefined intervals.

### Developers

Developers are responsible for signing, logging, and distributing their artifacts, and for publishing a policy. A policy is the trust material required to validate developer artifacts. It consists of:

* One or more Ed25519 signing keys
* A signature threshold (≤ number of keys)
* A Sigsum policy (one or more Sigsum logs and their keys, plus a witness policy)

Developers may also publish a reference hostname that is enrolled with the same policy. Artifacts are signed using any threshold of the policy’s keys, and each signature carries a Sigsum proof satisfying the Sigsum policy.

### Website Administrators

Website administrators enroll using a developer-provided policy (optionally referencing the developer’s reference hostname) and deploy the developer’s artifacts.

### Users

Users download the most recent enrollment list from a CDN and verify its freshness and consensus using the embedded trusted-organization keys in the browser component. When visiting a site, the browser checks the local enrollment list. If the site is enrolled, it fetches the site’s enrollment policy from the site itself and verifies it against the policy hash embedded in the local list. If a reference hostname is provided, the browser also verifies that the current site’s policy hash matches the reference’s (e.g., `submissions.webcat.example` matches `securedrop.org`). The verified enrollment policy is then used to validate developer artifacts.

## Acknowledgements
Thanks to [smaury](https://github.com/smaury) of [Shielder](https://www.shielder.com/) and to [antisnatchor](https://github.com/antisnatchor) of [Persistent Security](https://www.persistent-security.net/) for their security-related insights. Thanks to [Giorgio Maone](https://github.com/hackademix) of the Tor Project for the development-related support. We are also working with, and taking inspiration from, the WAICT working group.
