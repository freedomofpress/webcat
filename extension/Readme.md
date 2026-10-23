## WEBCAT Browser Extension

The extension is written in TypeScript, using the Manifest V3 API. Chromium is not supported, as the extension relies heavily on intercepting and modifying network requests and responses, which Chromium does not allow in Manifest V3. There are no external runtime dependencies: the Sigsum, Sigstore and CometBFT clients are maintained by the Freedom of the Press Foundation and, like the rest of the extension, use only the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). The only exception is in the WebAssembly hooks, where a synchronous SHA256 function is needed in order to hook synchronous WebAssembly methods and Worklets, where `crypto` is not available.

The latest tagged release is generally published on the [Mozilla Add-ons store](https://addons.mozilla.org/en-US/firefox/addon/webcat/).

### Build

Install build dependencies:

`npm install`

Compile the TypeScript and bundle it with [Vite](https://vite.dev):

`npm run build`

The output will be in `./dist/bundle.js` and `./dist/hooks/`. Everything else in the extension folder does not need any action.

Alternatively, `make package` will install, build, fetch the current enrollment list and package the extension, saving the archive as `../dist/webcat-extension.zip`. The archive can then be loaded in `about:debugging` as a temporary add-on. `make package-test` builds with `VITE_TESTING=true`, which disables minification and mocks the light client, and is what the integration tests use.

The extension can also be built as an npm library with `npm run build:lib`. API docs are generated with [Typedoc](https://typedoc.org).

The npm package also ships the test build, as `@freedomofpress/webcat/test-extension.zip`, for local development tools such as [webcat-cli](https://github.com/freedomofpress/webcat-cli). It trusts any enrollment list served at `http://localhost:1234/` (the light client is mocked), allows ports 8080 and 8443, and upgrades `http://` to `https://` on port 8443. It is unsigned, so Firefox only loads it as a temporary add-on: use it in a throwaway profile, never in a browser you use day to day.

### Tests

Unit tests use [vitest](https://vitest.dev/) and run natively, with the browser APIs mocked:

`npm run test`

Tests in `tests/webcat/` cover the verification logic, tests in `tests/browser/` the wrappers around the WebExtension APIs. `npm run coverage` also prints a coverage report.

Integration tests are in [`../test/`](../test/README.md). They use pytest to run Firefox and Tor Browser with the `package-test` archive (or the library build) installed, and check the test apps. CI runs them on Firefox, Firefox ESR and Tor Browser at the Standard, Safer and Safest security levels.

### Linting

The project uses [dpdm](https://github.com/acrazing/dpdm) to catch circular imports, [eslint](eslint.config.mjs) for linting and [prettier](https://prettier.io/) for sorting imports and style consistency. All three are run together with:

`npm run lint`

To check for issues without auto-fixing (this is what CI runs):

`npm run lint:check`

### How it works

For an overview of the verification flow and the response validation logic, see [Towards auditable web application runtimes](https://securedrop.org/news/webcat-towards-auditable-web-application-runtimes/) and the [specifications](https://github.com/freedomofpress/webcat-spec).
