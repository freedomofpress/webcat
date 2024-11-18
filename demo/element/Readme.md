### How to package Element

1. [Install the debian package.](https://github.com/element-hq/element-web/blob/develop/docs/install.md#debian-package)
2. Due to how the WASM matrix SDK is loaded, we need to grab the hash of the crypto-sdk WASM at runtime (or dig in the packed js and extract the base64 of it manually). In a browser with the extension installed, visit a live copy of Element: look into the console and grab any WASM sha256 hash that gets printed in the console  by the hooking scripts.
3. Build and sign the manifest:

    1. `python3 signing/main.py /usr/share/element-web --output manifest.json --canonical_output canonical_manifest.json --app_version 2 --webcat_version 1 --signatures 2 --bundle_output sigstore_bundle `
    2. When asked for additional WASM hashes, input the one(s) collected above.
    3. Proceed with the signatures.

Of course the webserver should be configure to be webcat compliant. Element also specifies the CSP policy in the main frame; every part of webcat expects that to be a HTTP header, so it's important to bring that policy also into the headers, and either remove it from the HTML (before signing), and if modified sync it in the two places.
