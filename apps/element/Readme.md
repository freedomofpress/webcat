### How to package Element
Tested on 5.0.44.

1. [Install the debian package.](https://github.com/element-hq/element-web/blob/develop/docs/install.md#debian-package)
2. Add the required `x-sigstore-headers` and `x-sigstore-signers` to the webserver configuration.
3. Add the following CSP to the webserver configuration (or adapt it to a more recent version, keeping in mind the CSP limitations in WEBCAT):
```
default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'wasm-unsafe-eval'; img-src * blob: data:; connect-src * blob:; font-src 'self' data: ; media-src * blob: data:; child-src blob: data:; worker-src 'self'; frame-src blob: data:; form-action 'self'; manifest-src 'self';
```
4. Check and edit the following configuration if needed, save it in `/usr/share/element-web/webcat.config.json`:
```
{
    "app_name": "Element",
    "app_version": "1.11.92",
    "comment": "https://github.com/element-hq/element-web/releases/tag/v1.11.92",
    "wasm": [],
    "default_csp": "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'wasm-unsafe-eval'; img-src * blob: data:; connect-src * blob:; font-src 'self' data: ; media-src * blob: data:; child-src blob: data:; worker-src 'self'; frame-src blob: data:; form-action 'self'; manifest-src 'self';",
    "extra_csp": {}
}
```
5. Build and sign the manifest, specifying the amount of signatures desired:
`python3 signing/signer.py /usr/share/element-web/ --output /usr/share/element-web/webcat.json --signatures 1`
