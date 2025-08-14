# WEBCAT V2

Some parts of the architecture are being reworked ahead of an alpha release (target: December 2025). Most information about web-app porting and compatibility is unchanged; the redesign primarily addresses centralization and censorship risks. Sigstore is being removed in favor of long-lived developer keys. Enrollment moves to a dedicated permissioned [CometBFT](https://github.com/cometbft/cometbft) blockchain. Developer signatures are still logged for transparency, but developers can choose their own log(s) and cosigning policy. User-facing indicators will reference well-known domains that publish the same policy (e.g., a project’s official website).

## Overview
![Diagram depicting the full architecture, as summarized below](./docs/architectureV2.svg)

[Click here for a PNG version.](./docs/architectureV2.png)

## Enrollment Blockchain

The enrollment blockchain has three roles:
* Log all enrollment transactions
* Process enrollment transactions
* Build daily enrollment lists

This is a permissioned chain run by a limited set of trusted organizations. External parties can audit the chain but do not participate in consensus. The chain governs enrollment, modification, and de-enrollment. Nodes (and validators) independently fetch the target host, observe the proposed change, and agree on both the observed state and the operation’s validity (e.g., you cannot de-enroll a domain that isn’t currently enrolled).

Once per day, the chain initiates a list-building transaction that deterministically applies the full history to produce the current enrollment list. That list is distributed to users' browsers at startup and at predefined intervals.

## Developers

Developers are responsible for signing, logging, and distributing their artifacts, and for publishing a policy. A policy is the trust material required to validate developer artifacts. It consists of:

* One or more Ed25519 signing keys
* A signature threshold (≤ number of keys)
* A Sigsum policy (one or more Sigsum logs and their keys, plus a witness policy)

Developers may also publish a reference hostname that is enrolled with the same policy. Artifacts are signed using any threshold of the policy’s keys, and each signature carries a Sigsum proof satisfying the Sigsum policy.

## Website Administrators

Website administrators enroll using a developer-provided policy (optionally referencing the developer’s reference hostname) and deploy the developer’s artifacts.

## Users

Users download the most recent enrollment list from a CDN and verify its freshness and consensus using the embedded trusted-organization keys in the browser component. When visiting a site, the browser checks the local enrollment list. If the site is enrolled, it fetches the site’s enrollment policy from the site itself and verifies it against the policy hash embedded in the local list. If a reference hostname is provided, the browser also verifies that the current site’s policy hash matches the reference’s (e.g., `submissions.webcat.example` matches `securedrop.org`). The verified enrollment policy is then used to validate developer artifacts.

