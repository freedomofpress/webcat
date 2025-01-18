### How to package Cryptpad
_Note_: while the following procedure has to be done per-instance, it would require minimal changes from the official projecty for it to be signed only once. Namely, config should be loaded as a fetched JSON or similar, and not sourced as a script.

1. [Install following the official guide.]([https://github.com/element-hq/element-web/blob/develop/docs/install.md#debian-package](https://docs.cryptpad.org/fr/admin_guide/installation.html))
2. Edit `/www/components/requirejs/require.js` and comment out the following line:
```
//Calling onNodeCreated after all properties on the node have been
//set, but before it is placed in the DOM.
if (config.onNodeCreated) {
//    config.onNodeCreated(node, config, moduleName, url);
}
```
The reason for this change is to prevent CSP failures where the iframe loads from the main origin and vice-versa. Since both share the same webroot, there is no reason to do it.
3. Collect the hases of the dynamically generated files:
```
# curl -s https://<host>/api/config | sha256sum
7c7825bbb497e77b8dd4619d036a583320951c2d38275c38a334ed4bf44a7696  -
# curl -s https://<host>/api/instance | sha256sum
388cbe353ff9353f59a8250b940de81b4b9fefc8da4ce8335d0aedaeaf7e6a48  -
# curl -s https://cryptpad.nym.re/api/broadcast | sha256sum
fefcb386310b7dfbd65849b0d78681862004dce1366c6f33a83cd86cc1473873  -
# curl -s https://<host>/extensions.js/ | sha256sum
aa806b924a9cb090e7cd47e2cf7c6d93c85804073d289c201a44635b03c7a65e  -
# curl -s https://<host>/customize.dist/login.js | sha256sum
157f0f6fcbcccdac2d0709120719d8e59e766bf3c4c6c9e655f5fe0bca6d3440  -
```

4. Build and sign the manifest:
    1. `python3 sign3.py /root/cryptpad/www/ --output webcat.json -a /api/config=7c7825bbb497e77b8dd4619d036a583320951c2d38275c38a334ed4bf44a7696 -a /api/instance=388cbe353ff9353f59a8250b940de81b4b9fefc8da4ce8335d0aedaeaf7e6a48 -a /extensions.js/=aa806b924a9cb090e7cd47e2cf7c6d93c85804073d289c201a44635b03c7a65e -a /customize.dist/login.js=157f0f6fcbcccdac2d0709120719d8e59e766bf3c4c6c9e655f5fe0bca6d3440 -a /api/broadcast=fefcb386310b7dfbd65849b0d78681862004dce1366c6f33a83cd86cc1473873`
    2. Additional WASM hashes are not needed.
    3. Proceed with the signatures.
5. Set the following CSP:
```
add_header content-security-policy "default-src 'none'; style-src 'unsafe-inline' 'self'; font-src 'self' data:; object-src 'none'; child-src https://cryptpad.nym.re; frame-src 'self' https://sandbox.cryptpad.nym.re; connect-src 'self' blob: https://cryptpad.nym.re https://sandbox.cryptpad.nym.re wss://cryptpad.nym.re *; img-src 'self' data: blob: https://cryptpad.nym.re; media-src blob:; frame-ancestors 'self' https://cryptpad.nym.re; worker-src 'self'; script-src 'self'";
```
6. Reminder that both the main domain and the sandbox domain must be independently enrolled. They share the same manifest and policy, but nonetheless in order for the iframes to work, this is mandatory.
