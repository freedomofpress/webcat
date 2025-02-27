### How to package Jitsi
Tested on 2.0.10008.

1. Install from the official guide.
2. Jitsi does not ship with a CSP policy by default. If installed via the official instructions, the web root is located at `/usr/share/jitsi-meet`. Jitsi has some inline scripts in the `index.html` and in some other html files. Since it is required to have no `unsafe-inline` script-src directive, and script hashes are also not supported, the inline scripts must to be moved into separate files. Furthermore, Jitsi uses SSI templating in their html to dynamically build the index and other pages. As a requirement, pages must be static in order for hashes to be computed and then matched.
To resolve both issues run, the script `compileSSI.py /usr/share/jitsi-meet /usr/share/jitsi-meet-compiled`. It will first build static files from the SSI, and then move any script to individual .js files and include them.
3. Adjust the following configuration to the correct version, if needed manually add any WASM hash the is embedded into JS/HTML instead of being a standalone file. Save it in `/usr/share/jitsi-meet-compiled/webcat.config.json`.

3. Use the signing script to sign the `/usr/share/jitsi-meet-compiled` folder:
`python3 signing/signer.py /usr/share/jitsi-meet-compiled --output /usr/share/jitsi-meet-compiled/webcat.json --signatures 1`

4. Replace `/usr/share/jitsi-meet` with the now compiled and signed version `/usr/share/jitsi-meet-compiled/`.

5. Add the CSP and sigstore headers to the nginx config file:

```
    [...]

    gzip_proxied no-cache no-store private expired auth;
    gzip_min_length 512;

    include /etc/jitsi/meet/jaas/*.conf;

    add_header content-security-policy "default-src 'self'; font-src 'self'; img-src 'self' data:; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-src 'none'; child-src 'none'; worker-src 'self';" always;
    add_header x-sigstore-signers '[{"identity": "signer1@domain1.com, "issuer": "https://accounts.google.com"}]' always;
    add_header x-sigstore-threshold "1" always;

    location = /config.js {
 
    [...]

    location ~ ^/(libs|css|static|images|fonts|lang|sounds|.well-known)/(.*)$
    {
        add_header content-security-policy "default-src 'self'; font-src 'self'; img-src 'self' data:; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-src 'none'; child-src 'none'; worker-src 'self';" always;
        add_header x-sigstore-signers '[{"identity": "signer1@domain1.com, "issuer": "https://accounts.google.com"}]' always;
        add_header x-sigstore-threshold "1" always;
        add_header 'Access-Control-Allow-Origin' '*';
        alias /usr/share/jitsi-meet/$1/$2;

        # cache all versioned files
        if ($arg_v) {
            expires 1y;
        }
    }

    [...]
```
