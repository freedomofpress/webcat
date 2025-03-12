## Webcat Browser Extension

The extension is written mostly in TypeScript, using the Manifest V2 API. It is very unlikely that a port to Manifest V3 would be possible, as it relies heavily on intercepting and modifying network requests and responses. There are no runtime dependencies, and it uses only the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) including the TUF, Sigstore and Sigsum clients. The only exception are the WebAssembly hooks where a synchronous SHA256 function is needed in order to hook synchronous WebAssembly methods.

### Build

Install build dependencies:

`npm install`

Compile the TypeScript and package it into a single file using [Vite](https://vite.dev):

`npm run build`

The output will be in `./bundle/bundle.js`. Everything else in the extension folder does not need any action. The extension can be loaded in debug mode by loading the `manifest.json` after the build command.

Alternatively, `make build` will build, package, and clean the extension, saving the archive as `../dist/webcat-extension.zip`.

### Tests

There is currently a very limited test suite supported, mostly to showcase the structure and scaffholding. Tests use [vitest](https://vitest.dev/) and can be run both natively, or in [playwright](https://playwright.dev/). In the future, while some test will keep running in both modes, some others will explicitly require the full browser environment.

`npm run test`

Or, for playwright:

```
npm install @vitest/browser playwright
npx playwright install
npm run test:playwright
```

### Linting

The project currently use [eslint](eslint.config.mjs) for linting and prettifier for sorting imports and style consistency. Both are run together with:

`npm run lint`

### Decision tree

```mermaid
flowchart TD
    A[User types example.com] --> B[Extension intercepts request]
    B --> C{Is example.com enrolled?}
    C -- No --> D[Allow request to proceed]
    C -- Yes --> E[Fetch policy hash]
    E --> F[Fetch manifest.json]
    F --> G{Headers valid?}
    G -- No --> H[Abort page load]
    G -- Yes --> I[Wait for manifest download]
    I --> J{Manifest downloaded successfully?}
    J -- No --> H
    J -- Yes --> K[Verify manifest signatures SigStore]
    K --> K2[Match manifest signers with policy hash]
    K2 --> L{Signatures valid?}
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
