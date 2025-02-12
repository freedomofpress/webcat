### How to package/install Globaleaks 
Tested on 5.0.44.

1. [Install the debian package](https://docs.globaleaks.org/en/stable/setup/).
2. Adjust the following configuration to the correct version, if needed manually add any WASM hash the is embedded into JS/HTML instead of being a standalone file. Check also that the different CSP for the different paths matches. Save it in `/usr/share/globaleaks/client/webcat.config.json`.
```
{
    "app_name": "GlobaLeaks",
    "app_version": "5.0.44",
    "comment": "https://github.com/globaleaks/globaleaks-whistleblowing-software/releases/tag/v5.0.44",
    "wasm": ["4b3ae4e84f416581bc6ed81f3702bd3530318bf7140b0f7f177adfeb074452c4"],
    "default_csp": "base-uri 'none';default-src 'none';form-action 'none';frame-ancestors 'none';sandbox;trusted-types;require-trusted-types-for 'script';report-uri /api/report;",
    "extra_csp": {
        "/": "base-uri 'none';connect-src 'self';default-src 'none';font-src 'self';form-action 'none';frame-ancestors 'none';frame-src 'self';img-src 'self';media-src 'self';script-src 'self';style-src 'self';trusted-types angular angular#bundler dompurify default;require-trusted-types-for 'script';",
        "/workers/crypto.worker.js": "base-uri 'none';default-src 'none';form-action 'none';frame-ancestors 'none';script-src 'wasm-unsafe-eval';sandbox;trusted-types;require-trusted-types-for 'script';report-uri /api/report;",
        "/viewer/index.html": "base-uri 'none';default-src 'none';connect-src blob:;form-action 'none';frame-ancestors 'self';img-src blob:;media-src blob:;script-src 'self';style-src 'self';sandbox allow-scripts;trusted-types;require-trusted-types-for 'script';"
    }
}
```
3. Edit `/usr/lib/python3/dist-packages/globaleaks/rest/api.py` to add the required `x-sigstore-signers` and `x-sigstore-threshold` headers.
4. Build and sign the manifest, specifying the amount of signatures desired:
`python3 signing/signer.py /usr/share/globaleaks/client --output /usr/share/globaleaks/client/webcat.json --signatures 1`
