# TestApp
The purpose of the `testapp` is to demo some advanced web features supported within this project.

### Manifest generation
To generate a valid manifest for deployment, use the signign script:

```
python3 signing/main.py ./testapp --output manifest.json --canonical_output canonical_manifest.json --app_version 2 --webcat_version 1 --signatures 2 --bundle_output sigstore_bundle 
```

### Deployment
The app requires the following CSP:

```
object-src 'none'; default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; frame-src 'none';
```

### Tests
1. `alert.js` attempts basic JS execution
2. `csp.js` tests whether `eval()` blocking is enforced by CSP
3. `import.js` tests an ES6 module import of `import_test.js`
4. `load_serviceworker.js` attempts to register the `workers/serviceworker.js` ServiceWorker
5. `load_sharedworker.js` attempts to register the `workers/sharedworker.js` SharedWorker
6. `load_worker.js` attempts to register the `workers/worker.js` Worker
7. `wasm_fetch.js` tests `WebAssembly.instantiateSreaming()` with a `fetch` Response as argument (`wasm/addThree.wasm`)
8. `wasm.js` tests `WebAssembly.instantiate()` with the raw bytes of `wasm/addTwo.wasm` as argument.

Expected output in the browser developer console, with the extension installed:


![Console log output of the testapp](console_log.png)

Note: ServiceWorkers get registered only once; also they are disabled in incognito mode.
