### How to package/install Globaleaks
Tested on 2024.12.1.

1. [Follow the official instructions.]([https://docs.globaleaks.org/en/stable/setup/](https://bitwarden.com/help/install-on-premise-linux/))
2. Copy the app assets from the docker container `bitwarden-web:/app` to the machine where the signing script can run.
3. Build and sign the manifest: `python3 signing.py --output app/webcat.json --signatures 1 app/`
4. Copy  back the signed manifest: `docker cp app/webcat.json bitwarden-web:/app/webcat.json`
5. Edit `bitwarden-nginx:/etc/nginx/security-headers-ssl.conf` to add the required `x-sigstore-signers` and `x-sigstore-threshold` headers.
6. Edit `bitwarden-nginx:/etc/nginx/conf.d/default.conf` to adjust the CSP to remove untrusted `frame-src` and `child-src` and disable `object-src`:

```
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://haveibeenpwned.com; child-src 'self'; frame-src 'self'; connect-src 'self' wss: https://api.pwnedpasswords.com https://api.2fa.directory; object-src 'none'";
```
7. Reload nginx in `bitwarden-nginx`.