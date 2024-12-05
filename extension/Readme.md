## Webcat Browser Extension

The extension is written mostly in TypeScript, using the Manifest V2 API. It is very unlikely that a port to Manifest V3 would be possible, as it relies heavily on intercepting and changing network requests and responses.

### Features

- No runtime dependencies: everything has been written from scratch and does not depend on any third-party package (no polyfills)
- Native crypto: every cryptographic operation, from TUF to Sigstore, to Webcat uses only the native [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- Small footprint: currently, the compiled code is ~30KB
- Failsafe: invalid scripts are discarded at the network level
- Fast: the extension's impact on non-enrolled websites is negligible

### Build

Install build dependencies:

`npm install`

Compile the TypeScript and package it into a single file using [Vite](https://vite.dev):

`npm run build`

The output will be in `./bundle/bundle.js`. Everything else in the extension folder does not need any action. The extension can be loaded in debug mode by loading the `manifest.json` after the build command.

Alternatively, `make build` will build, package, and clean the extension, saving the archive as `../dist/webcat-extension.zip`.

## Validation logic

_WARNING_: experimental diagrams. Conformity with the code to be verified.

### Decision tree

```mermaid
flowchart TD
    A[User types www.example.com] --> B[Extension intercepts request]
    B --> C{Is www.example.com enrolled?}
    C -- No --> D[Allow request to proceed]
    C -- Yes --> E[Fetch policy hash]
    E --> F[Fetch manifest.json]
    F --> G{Headers valid?}
    G -- No --> H[Abort page load]
    G -- Yes --> I[Wait for manifest download]
    I --> J{Manifest downloaded successfully?}
    J -- No --> H
    J -- Yes --> K[Verify manifest signatures]
    K --> L{Signatures valid?}
    L -- No --> H
    L -- Yes --> M[Download main page content]
    M --> N[Check main page hash]
    N --> O{Main page hash valid?}
    O -- No --> H
    O -- Yes --> P[Verify subresources CSP and hashes]
    P --> Q{Subresources valid?}
    Q -- No --> H
    Q -- Yes --> R[Allow page to load]
```

### Sequence diagram

```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant Extension
    participant Server

    User ->> Browser: Types www.example.com
    Browser ->> Extension: Sends request to load the page
    Extension ->> Extension: Checks if www.example.com is in the internal list
    alt Not Enrolled
        Extension ->> Browser: Allow request to proceed
    else Enrolled
        Extension ->> Server: Fetch policy hash
        Extension ->> Server: Fire async request to www.example.com/manifest.json
        Server -->> Extension: Returns headers
        Extension ->> Extension: Check header conformity
        alt Header Invalid
            Extension ->> Browser: Abort page load
        else Header Valid
            Extension ->> Extension: Wait for manifest to download
            alt Manifest Download Fails
                Extension ->> Browser: Abort page load
            else Manifest Downloaded
                Extension ->> Extension: Verify manifest signatures
                alt Signature Invalid
                    Extension ->> Browser: Abort page load
                else Signature Valid
                    Extension ->> Server: Download main page
                    Server -->> Extension: Returns main page content
                    Extension ->> Extension: Check main page hash
                    alt Main Page Hash Invalid
                        Extension ->> Browser: Abort page load
                    else Main Page Hash Valid
                        Extension ->> Extension: Verify subresources (CSP and hashes)
                        alt Subresource Verification Fails
                            Extension ->> Browser: Abort page load
                        else All Subresources Verified
                            Extension ->> Browser: Allow page to load
                        end
                    end
                end
            end
        end
    end
```
