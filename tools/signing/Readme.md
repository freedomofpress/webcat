# Manifest building and signing
The purpose of this script is to build and sign a `manifest.json` file for a webcat-enabled single page web application. See the [Developer Guide](../../docs/DeveloperGuide.md) for a list of requirements.

## Installation
Install the requirements in a new python3 virtualenv.
```
cd webcat/tools/signing
python3 -m venv .venv
pip3 install -r requirements.txt
```
Test the script.
```
python3 signer.py
```

## Signing Steps
Steps maarked with `*` are optional.

 1. _Prepare the web application assets_: create a folder with all the application executable assets, namely `html`, `htm`, `css`, `js`, `mjs` and `wasm` files. Not that `wasm` files can have any extension, because they are fetched and then executed, while the other file extensions require to be server with the correct file type. It is possible to use any other file extension if the web server serves them with the proper mime type, but the signing script would need to be modified to include those extensions.
 2. *_Collect any WebAssembly blobs_: those that do not have the `wasm` extension or blobs that are embedded in JavaScript files.
 3. *_Calculate the sha256 of the raw collected WASM blobs_: save the hex encoded hashing result.
 4. *_Collect any extra executable file_: those that were not easily exportable as part of the application code, or that have a different extension.
 5. *_Calculate the sha256 of the extra executable files_: save the hex encoded hashing result.
 6. _Choose the CSP(s)_: read the documentation in the [Developer Guide](../../docs/DeveloperGuide.md) to see what is allowed or not. An unlimited number of per path CSP are supported.
 7. _Prepare the application configuration_: complete the `webcat.config.json` boilerplate below with the collected information, and place it in the app folder.

	```
	{
	    "app_name": "<free text>",
	    "app_version": "<should be incremental>,
	    "comment": "<link to source code>",
	    "wasm": ["<wasm hash A from step 3>", "<wasm hash B from step 3>"],
	    "default_csp": "<default CSP from step 6>",
	    "extra_csp": {
	    	"/path/to/worker.js": "<CSP for a worker>",
	     	"/path/to/iframe.html": "<CSP for an iframe>",
	      	"...": "..."
	    },
	    "files": {
	        "<web path A from step 4>": "<hash A from step 5>",
	        "<web path B from step 4>": "<hash B from step 5>",
	    }
	}
	```

	  To see examples that uses all the optional features, see [Cryptpad](../../apps/cryptpad) for extra files, and [Globaleaks](../../apps/globaleaks) for multiple CSPs.
  
  8. _Proceed with the signatures_: the signing script will invoke Sigstore. If a browser is available, the OIDC login to Fulcio will be automatically opened, otherwise the link will be shown. `python2 signer.py --signatures 1 --output app/webcat.json app/`

  10. _Insert the signing identity_: after the signing, the script will prompt asking, in order, which identities have been used for the various signatures. Identities are always emails, for instance, in the case of a Github OIDC login, the identity will be the primary email.

For signed manifest examples, see some of the currently deployd `webcat.json` files: [testapp/webcat.json](https://testapp.nym.re/webcat.json), [Jitsi](https://jitsi.nym.re/webcat.json)

_TODO: the manual input for identities can be eliminated, as the "signatures" structure in the manifest JSON should be an array and not an object._

For signed manifest examples
