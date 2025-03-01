### How to package Standardnotes

1. [Build the web app package following the official instructions.](https://github.com/standardnotes/app?tab=readme-ov-file#self-hosting-the-web-app)
2. The output is in `app/packages/web/dist`. There is an inline scripot in `index.html` containing the API configuration, move that code to a dedicated file such as `config.js` and include it.
3. There is an inline assembly module, and as such its hash should be captured and computed before signing. In my case this was `9d7135eb90de07fa8c51a78d919718d5c3bdc51117e46199baf4dc0f59b1db9f`.
4. Run the signing script on the `dist` folder.
5. Set up the following CSP:
```
content-security-policy: default-src 'self'; base-uri 'self'; connect-src api.standardnotes.com sync.standardnotes.org files.standardnotes.com ws://sockets.standardnotes.com raw.githubusercontent.com listed.to blob: data:; font-src * data:; form-action 'self'; img-src 'self' * data: blob:; manifest-src 'self'; media-src 'self' blob: *.standardnotes.com; object-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline' 'unsafe-hashes'; worker-src 'self'; frame-src 'none';
```
6. The CSP was derived from the official one at https://app.standardnotes.com. Registration will likely not work because the Captcha from the original API is loaded as an iframe from a non enrolled origin, and as such it is blocked by the CSP.
