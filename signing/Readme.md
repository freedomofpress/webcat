# Manifest building and signing
The purpose of this script is to build and sign a `manifest.json` file for a webcat-enabled single page web application.

### Manifest structure

Example from the `testapp`:

```
{
    "manifest": {
        "info": {
            "app_version": 2,
            "webcat_version": 1
        },
        "files": {
            "/": "c92c967effd335f55de516969628757eb280185fa43efd0ad0aae124f49226bd",
            "/js/load_serviceworker.js": "d95a19dd842939d2f5414f0dec6394ec405abb485aa76f4ffa0c4e10a9a5d998",
            "/js/load_sharedworker.js": "2f0ff10c61ad3d19269c33af6957f4942ed3c5274f702d346e945a5502b392e0",
            "/js/wasm.js": "898a77a26b49eb2ac3ed4565ffac433ea606d7d3b4dd67cc9636d020ac525d8c",
            "/js/wasm_fetch.js": "e7844d74373b5becca2c66f11e7ade13a3eb2b5ca60b6ed245fdf18a32d6a671",
            "/js/csp.js": "70e0bcb115f28e335748afe41d7cebbdb4c77c14aa72cc8445e5a8480fea34cb",
            "/js/import.js": "257f0c825ba17df68f26dda89dd6d16db51694e627d8b7ffa0ba2f07796bc37f",
            "/js/load_worker.js": "5c900ba14d7cd0868fb9525e8bd5754906539992658185e60f4694483d49865d",
            "/js/alert.js": "eb6d9606b7650b27e2ae5e0884c2df53380d9457689807b21405c9e52d7a1b55",
            "/js/import_tester.js": "3dde8807987f65f987170d5d0e08c5274290703e1b690189ba2e66ef60941aed",
            "/workers/serviceworker.js": "0359315639b95496744a0abee9ad507fcb8eb7832c86e1091ce6785011ba03d3",
            "/workers/worker.js": "0d1412471e5ac5ed76f075e770aff104dc24a384ab6c1376bed5d129b6cb2f18",
            "/workers/sharedworker.js": "b811ee381ca722f4fb0b532ad4f7f5d4978c70765343ea2f2806404f1ea51498"
        },
        "wasm": [
            "70f56f000fe939f330736d6cf619c4d779112dde3a5c4dc28b9fd36f5a2ca0fe",
            "f82943be0905ece191cc2f4333861e2846d42c3ec64a7ea24df21a322f1b3013"
        ]
    },
    "signatures": {
        "identity1@freedom.press": {<sigstore bundle for identity1>},
        "identity2@lsd.cat": {<sigstore bundle for identity2>}
    }
}                                                                                                                                                                                                      

```

In practice, every "executable" file must be mapped to its sha256 hash. Since WebAssembly gets executed as a bytestring or a module, and not as a file, it does not have an associated path, but the list of allowed bytecodes is just an array of hashes.

`app_version` is supposed to prevent rollback attacks and force updates in future iterations of the project.

`signatures` is a `key: value` object that maps a signing identity to the corresponding Sigstore bundle for the string representation fd the [canonical JSON](https://wiki.laptop.org/go/Canonical_JSON) version of the `manifest` block.

### Flow
1. The script will ask for additional WASM hashes to be manually included (for instance in cases of embedding WASM into JS files, see [wasm-pack](https://github.com/rustwasm/wasm-pack/issues/1074)).
2. The script will traverse the app path and hash every `html`, `htm`, `js`, `mjs`, `css`, `wasm`.
3. The script will generate the manifest JSON file and conicalize it
4. Depending on the numnber of signatures required, is it then possible to sign the manifest via the Sigstore browser interactive flow
5. The script will ask for the corresponding identities that resulted from the signing flow
6. The script will write a valid manifest.json ready to be deployed

### Command line help
```
Generate a manifest JSON for web files.

positional arguments:
  directory             Directory to scan

options:
  -h, --help            show this help message and exit
  --output OUTPUT       Output final manifest JSON file with signatures
  --canonical_output CANONICAL_OUTPUT
                        Output canonical manifest JSON file
  --app_version APP_VERSION
                        Application version (default: 1)
  --webcat_version WEBCAT_VERSION
                        Webcat version (default: 1)
  --signatures SIGNATURES
                        Number of required Sigstore signatures (default: 1)
  --bundle_output BUNDLE_OUTPUT
                        Path to save Sigstore bundles

```

### Example
Example with building and signing a manifest for `testapp` with two identities.

```
python3 script.py testapp/ --output manifest.json --canonical_output canonical_manifest.json --app_version 2 --webcat_version 1 --signatures 2 --bundle_output sigstore_bundle

Do you want to add another WASM hash manually? (yes/no): no
Go to the following link in a browser:

	https://oauth2.sigstore.dev/auth/auth?response_type=<snip>
Enter verification code: <redacted>>
Using ephemeral certificate:
-----BEGIN CERTIFICATE-----
MIICzTCCAlOgAwIBAgIURdGWanHVk2jnET6dozJk/12dyC0wCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjQxMDIzMjAzOTIzWhcNMjQxMDIzMjA0OTIzWjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAE3pOnBeBaNi9ThJEQNaL2vhtVgbOLUzc40OVt
RWV0HTWHcdbRNf/1ej6n9zFzCHlwzkzF1ZEykLVSAhQCBvpO56OCAXIwggFuMA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUbWzQ
PoQ4DA6QD5pA0Dyaj6CXGg4wHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y
ZD8wIgYDVR0RAQH/BBgwFoEUZ2l1bGlvQGZyZWVkb20ucHJlc3MwKQYKKwYBBAGD
vzABAQQbaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tMCsGCisGAQQBg78wAQgE
HQwbaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tMIGKBgorBgEEAdZ5AgQCBHwE
egB4AHYA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4AAAGSuxsE2QAA
BAMARzBFAiA/8jWq7xR8k/lV1FK5p6ImfpUMKZE+4T1nav9TytP75QIhAPHci8Xp
mxWOl2t9mJXDk8nQUUsdUH1D1jPL4KYjgF0JMAoGCCqGSM49BAMDA2gAMGUCMQCU
gMwl31wEzhuc6wSOSHG3pv69Of8krifwfA/IXWMUTqjXcwOp88lushpHrMxYSDUC
MFc50S/5Gct3YwmtXEFOnhoIjN8OeMWxfOYdYcbRwRM0TAz9vMgX+PUZlPD9XiZp
NA==
-----END CERTIFICATE-----

Transparency log entry created at index: 143035602
MEQCIG0VMRGVt6rRaleetV2DrvnO5hRpcbb04/vQfdPo97VDAiAJp7rANpeNYQxeGrhuOnb6xltrCfHqnig33fjrjIt+CA==
Sigstore bundle written to sigstore_bundle_sig_1.json
Successfully signed canonicalized_manifest.json and saved the bundle to sigstore_bundle_sig_1.json
Go to the following link in a browser:

	https://oauth2.sigstore.dev/auth/auth?response_type=<snip>
Enter verification code: <redacted>
Using ephemeral certificate:
-----BEGIN CERTIFICATE-----
MIICzTCCAlOgAwIBAgIUJ3TntLtTuykHap9mzb6WIHGfXhgwCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjQxMDIzMjAzOTM5WhcNMjQxMDIzMjA0OTM5WjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEzto0p8f9TvcKMW5P5z5RqaVauzcjE2K2n9ek
JgF5ys2OqA0TNCdhU7k4F8CpsGNEkJ/OpOwGN44RvWxH4EfLtqOCAXIwggFuMA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUh17d
r8leFLXrBY/cHQvr1D4T9E0wHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y
ZD8wHAYDVR0RAQH/BBIwEIEOZ2l0aHViQGxzZC5jYXQwLAYKKwYBBAGDvzABAQQe
aHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoMC4GCisGAQQBg78wAQgEIAwe
aHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoMIGKBgorBgEEAdZ5AgQCBHwE
egB4AHYA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4AAAGSuxtFTwAA
BAMARzBFAiEA7TS0EujCnoVtqacrYB/w/7Upu5qgcmc1WFpwI4o3uWACICtc6YWI
cKM8zJsK3PB21U4jF73BmRJB8LHMz+UNoKa2MAoGCCqGSM49BAMDA2gAMGUCMQC3
TnPcLSWt2I2EM/K68z1RSus8e9sMVLrn2TS4e50Mwy45aeW5Zzt8UWE7PS3W5JwC
MBGSstOrsDBmrZkW4mFhbmI+V5AfMhG86pfkQBNYAQVKAY++mj3XfVoEiXxhtw8L
4w==
-----END CERTIFICATE-----

Transparency log entry created at index: 143035620
MEUCIDzcy9cN4gl/+SUE4PtisJkcZToMueQ+LDCe+VStEoo2AiEAu6P/uofJKzfBnsb9YEHxQMcKTNpXrJhtaTJfebjHyQs=
Sigstore bundle written to sigstore_bundle_sig_2.json
Successfully signed canonicalized_manifest.json and saved the bundle to sigstore_bundle_sig_2.json
Enter signer identity for bundle sigstore_bundle_sig_1.json (e.g., email): identity1@freedom.press
Enter signer identity for bundle sigstore_bundle_sig_2.json (e.g., email): identity2@lsd.cat

```