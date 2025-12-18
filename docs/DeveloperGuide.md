# Developer Guide
The purpose of this document is to lay out guidelines for compatibility of web-applications with this project.

## Conent Security Policy
CSP requirements are being dicussed more in detail in https://github.com/freedomofpress/webcat/issues/9.

However, some core requirements are unlinkely to change, as listed below.

### default-src
Only allowed attributes are:
 - `self`
 - `none`

If `default-src` is not `none`, than it is required to specify `object-src`, `child-src` or `frame-src` and `worker-src`.

### script-src, script-src-elem
Only allowed attributes are:
 - `none`
 - `self`
 - `wasm-unsafe-eval`

Note `sha-abc` format, while secure, breaks some assumptions about the sandbox and how the `WebAssembly` hooks work, thus it is not allowed.

### style-src, style-src-elem
Only allowed attirbutes are:
 - `none`
 - `self`
 - `sha-abc`
 - `unsafe-inline`*
 - `unsafe-hashes`*

* are allowed due to every tested application making use of it. When developing or updating a new application, if possible, it would be better to avoid it to ensure future compatibility, as the end goal is to eventually drop support for it.

### object-src
Only allowed attirbutes are:
 - `none`

Must be `'none`' if `default-src` is not `'none'`, otherwise it can be omitted.

### frame-src, child-src
Only allowed attirbutes are:
 - `none`
 - `self`
 - `blob:`
 - `data:`
 - `<external sources>`*

* external sources needs to be enrolled in WEBCAT too. At manifest parsing, it is checked whether any external origin is enrolled, or the validation fails. Then, upon loading, any external origin is fully validated th same as the main_frame.

Either one of the two must be set if `default-src` is not `'none'`, otherwise it can be omitted.

### worker-src
Only allowed attirbutes are:
 - `none`
 - `self`

Must be set if `default-src` is not `'none'`, otherwise it can be omitted.


### Everything else (img-src, connect-src, etc)
Everything else does not currently have limitations.

## Server generated content
Since pages need to be signed and remain static, both HTML and scripts must not change after deployment or have any server generated content. Server generated content can still be sourced and used via `fetch` request, `image` objects and so on. This si to prevent runtime code from changing.
HTML content can still be changed via DOM manipulation via Javascript, although the CSP will prevent execution via `eval()` or inline `script` tags.

## Customization
Some apps like Jitsi currently allow for customization of configuration and of some HTML elements for branding purposes. While this does not directly affect the workings of the integrity guarantees in itself, it would force every instance to sign their own manifest instead of using and official one and scoping their config and branding outside signed files.

The limitation with Jitsi is that configuration is written in a Javascript file, namely `config.js` and since it is sourced as a script it must be signed. On the contrary, Element sources per-instance configuration from a JSON file fetched dynamically, and as such it is not subject to signing or restrictive CSP policies.
Similarly, branding in Jitsi is handled by editing HTML files such as `head.html` and then those are dynamically included server side using SSI templates. Again, this hinders the possibility of signing the index as a static file since instance are expected to edit these components and the final file is rendered by the server. Instead, HTMl branding should be specified in non-executable configurable files, such as JSON, and then dynamically written in the DOM from authorized scripts.

## Routing
Since server generated pages cannot work, in general it is expected that the application is launched from the root and then uses anchor navigation. Non anchor navigation is still supported, and every file not found in the manifest is tentatively hashed against the index hash in the manifest, as it is the case for Jitsi (a room name is a random path, and we cannot expect that to be present in the manifest, however we expect that to be handled by a url rewrite and sent to the index, which is present in the manifest).

## Signing
For signing see the [signing script](../tools/signing). In the future, the will be instructions on how to integrate signing in a CI pipeline, since that is already supported by Sigstore.
