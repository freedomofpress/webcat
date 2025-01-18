### How to package/install Globaleaks

1. [Follow the official instructions.]([https://docs.globaleaks.org/en/stable/setup/](https://bitwarden.com/help/install-on-premise-linux/))
2. Copy the app assets from the docker container `bitwarden-web:/app` to the machine where the signing script can run.
2. Build and sign the manifest:
    1. `python3 signing/main.py /path/to/app --output webcat.json`
    2. Additional WASM hashes are not needed.
    3. Proceed with the signatures.
3. Edit `bitwarden-nginx:/etc/nginx/security-headers-ssl.conf` to add the required `x-sigstore-signers` and `x-sigstore-threshold` headers.
4. Edit `bitwarden-nginx:/etc/nginx/conf.d/default.conf` to adjust the CSP to remove untrusted `frame-src` and `child-src` and disable `object-src`:

```
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://haveibeenpwned.com; child-src 'self'; frame-src 'self'; connect-src 'self' wss://bitwarden.nym.re https://api.pwnedpasswords.com https://api.2fa.directory; object-src 'none'";
```
