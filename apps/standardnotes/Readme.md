### How to package Standardnotes

1. [Build the web app package following the official instructions.](https://github.com/standardnotes/app?tab=readme-ov-file#self-hosting-the-web-app)
2. The output is in `app/packages/web/dist`.
3. There is an inline assembly module, and as such its hash should be captured and computed before signing. In my case this was `9d7135eb90de07fa8c51a78d919718d5c3bdc51117e46199baf4dc0f59b1db9f`.
4. Run the signing script on the `dist` folder. When prompted, manually add the extra WASM hash.
5. Set up the following CSP:
```
content-security-policy: default-src https: 'self'; base-uri 'self'; connect-src api.standardnotes.com sync.standardnotes.org files.standardnotes.com ws://sockets.standardnotes.com raw.githubusercontent.com listed.to blob: data:; font-src * data:; form-action 'self'; img-src 'self' * data: blob:; manifest-src 'self'; media-src 'self' blob: *.standardnotes.com; object-src 'none'; script-src 'self' 'sha256-r26E+iPOhx7KM7cKn4trOSoD8u5E7wL7wwJ8UrR+rGs=' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline' 'unsafe-hashes'
```
6. The CSP was derived from the official one at https://app.standardnotes.com. Hashes might differ, and in this guide we applied some changes, mostly more restrictive but in the `style-src` side actually less restrictive. It has to be noted that Standard Notes does require `unsafe-hashes`, but not `unsafe-inline` as inline CSS is allowed via specific hashes.
