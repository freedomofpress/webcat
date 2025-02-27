# Web-based Code Assurance & Transparency (WEBCAT)
![webcat logo dark](./docs/icons/dark/256/webcat.png#gh-dark-mode-only)
![webcat logo light](./docs/icons/light/256/webcat.png#gh-light-mode-only)

The purpose of this project is to showcase an architectural framework for providing blocking code signing, integrity and transparency checks for browser-based single page applications. It do so, it mostly leverages existing teschnologies and community infrastructure, including [Sigstore](https://sigstore.dev), [Sigsum](https://sigsum.org), [The Update Framework](https://theupdateframework.io/). The browser extension does not have any runtime dependency, and all the cryptographic operations are performed using only the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). Runtime policy enforcement in the enrolled domains is enforced by the browser [CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP).

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

The following test domains are available, keeping in mind that their only purpose is for demoing and showcasing. As such, they are **not secure**, **well-maintained**, or guarantee any kind of **data retention**. A test enrollment server and list distributore, without guarantees is available at `https://transparency.cat/api/` and `https://transparency.cat/update/`.

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




