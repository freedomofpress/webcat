### How to package Jitsi
1. Jitsi does not ship with a CSP policy by default. If instaeed via the official instructions, the web root is located at `/usr/share/jitsi-meet`. Jitsi has some inline scripts in the `index.html` and in some other html files. Since it is required to have no `unsafe-inline` script-src directive, and we highlighy discourage the use of script hashes, as a first thing these scripts need to be moved to dedicated js files and sourced with `<script src=""></script>`. Convert the [highlighted lines in index.html to](https://github.com/jitsi/jitsi-meet/blob/298279a95690a1b89bf4b3b664e0dae42c7e2802/index.html#L15C0-L199C30):
```
<script src="/index-1.js"></script>
<script src="/index-2.js"></script>
<script src="/config.js"></script>
<script src="/interface_config.js"></script>
```
2. Look for every other inline `<script>` tag and repeat the procedure (most files that need changes are in `/static`).
3. Jitsi heavily uses SSI templates for branding, which cannot work because clearly the signed version is then different from the one rendered server side. [Example in index.html](https://github.com/jitsi/jitsi-meet/blob/298279a95690a1b89bf4b3b664e0dae42c7e2802/index.html#L202C1-L206C76):
```
<!--#include virtual="title.html" -->
<!--#include virtual="plugin.head.html" -->
<!--#include virtual="static/welcomePageAdditionalContent.html" -->
<!--#include virtual="static/welcomePageAdditionalCard.html" -->
<!--#include virtual="static/settingsToolbarAdditionalContent.html" -->
```
To resolve this issue, run the script `compileSSI.py` in this folder on the Jitsi web root. Generously produced by ChatGPT, the script simply performs the same substitution that the server would do while encountering the `include` directive.
4. Use the signing script to sign the `jitsi-meet` folder.
5. Edit Jitsi nginx config to add the following CSP on all served paths:
```
...
    gzip_proxied no-cache no-store private expired auth;
    gzip_min_length 512;

    include /etc/jitsi/meet/jaas/*.conf;

    add_header content-security-policy "default-src 'self'; font-src 'self'; img-src 'self' data:; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; object-src 'none';";

    location = /config.js {
...

    location ~ ^/(libs|css|static|images|fonts|lang|sounds|.well-known)/(.*)$
    {
        add_header content-security-policy "default-src 'self'; font-src 'self'; img-src 'self' data:; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; object-src 'none';";
        add_header 'Access-Control-Allow-Origin' '*';
        alias /usr/share/jitsi-meet/$1/$2;

        # cache all versioned files
        if ($arg_v) {
            expires 1y;
        }
    }

...
```
