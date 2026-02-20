# Web-based Code Assurance and Transparency (WEBCAT)
![webcat logo dark](./docs/icons/dark/256/webcat.png#gh-dark-mode-only)
![webcat logo light](./docs/icons/light/256/webcat.png#gh-light-mode-only)

The extension is available to end-users on the Mozilla Add-ons website (AMO):
 - [Get the extension](https://addons.mozilla.org/en-US/firefox/addon/webcat/)
 - [User guide](https://docs.webcat.tech/for-users.html)

To get started as website owner, developer, contributor, or researcher see the following resources:
  - [Project Website](https://webcat.tech)
  - [Documentation](https://docs.webcat.tech)
  - [Research](https://docs.webcat.tech/research.html)

To report issues, please us the [bugtracker of this repository](https://github.com/freedomofpress/webcat/issues).

The purpose of this project is to develop a framework that provides blocking code signing, as well as integrity and transparency checks for browser-based applications. In doing so, it primarily leverages existing technologies and community infrastructure, including [Sigsum](https://sigsum.org), [Sigstore](https://sigstore.dev) and [CometBFT](https://github.com/cometbft/cometbft). The browser extension has no external runtime dependencies, and all cryptographic operations are performed using only the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). Runtime policy enforcement in the enrolled domains is handled by the browser's [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP).

The project has been originally written as a master's thesis for the [Master Computer Security at the Vrije Universiteit Amsterdam](https://vu.nl/csec) and the [University of Amsterdam](https://uva.nl), sponsored by the [Freedom of the Press Foundation](https://freedom.press). [The full dissertation is available on ePrint](https://eprint.iacr.org/2025/797.pdf). It has since evolved to address censorship risks, centralization, and single points of failure concerns.

WEBCAT is:
 1. [An enrollment consensus system](https://github.com/freedomofpress/webcat-infra-chain)
 2. [A set of specifications](https://github.com/freedomofpress/webcat-spec)
 3. [A Firefox (MV2) extension](./extension/)
 4. [A CLI for developers and hosters](https://github.com/freedomofpress/webcat-cli)
 5. Some dependencies, such as [sigsum-ts](https://github.com/freedomofpress/sigsum-ts), [cometbft-ts](https://github.com/freedomofpress/cometbft-ts) and [sigstore-browser](https://github.com/freedomofpress/sigstore-browser).

**This is currently experimental software and should not be used in production**.

See [The long and winding road to safe browser-based cryptography](https://securedrop.org/news/browser-based-cryptography/), [Introducing WEBCAT](https://securedrop.org/news/introducing-webcat-web-based-code-assurance-and-transparency/) and [Towards auditable web application runtimes](https://securedrop.org/news/webcat-towards-auditable-web-application-runtimes/) for additional context.

## Overview
![Diagram depicting the full architecture, as summarized below](./docs/architectureV2.svg)

[Click here for a PNG version.](./docs/architectureV2.png)

## Acknowledgements
Thanks to [smaury](https://github.com/smaury) of [Shielder](https://www.shielder.com/) and to [antisnatchor](https://github.com/antisnatchor) of [Persistent Security](https://www.persistent-security.net/) for their security-related insights. Thanks to [Giorgio Maone](https://github.com/hackademix) of the Tor Project for the development-related support. We are also working with, and taking inspiration from, the WAICT working group.
