### How to package/install Globaleaks

1. [Install the debian package.]([https://github.com/element-hq/element-web/blob/develop/docs/install.md#debian-package](https://docs.globaleaks.org/en/stable/setup/))
2. Build and sign the manifest:

    1. `python3 signing/main.py /usr/share/globaleaks/client --output manifest.json --canonical_output canonical_manifest.json --app_version 2 --webcat_version 1 --signatures 2 --bundle_output sigstore_bundle `
    2. Additional WASM hashes are not needed.
    3. Proceed with the signatures.
3. Edit `/usr/lib/python3/dist-packages/globaleaks/rest/api.py` to add the required `x-sigstore-signers` and `x-sigstore-threshold` headers.
4. Edit `/usr/lib/python3/dist-packages/globaleaks/handlers/staticfile.py` so that all static resources are served with the same CSP (quick and dirty: remove `if index.html`).
