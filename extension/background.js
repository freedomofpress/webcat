var server = 'https://preload.cat'
var tabs = {};
const debug = false;

let db;
const request = indexedDB.open("webcat");
request.onerror = (event) => {
    console.error("The extension cannot run without database access!");
};
request.onsuccess = (event) => {
    db = event.target.result;
};

// Let's keep things clean and prune our array when a tab is closed
browser.tabs.onRemoved.addListener(tabCloseListener);
 
// On first extension installation download and verify a full list
browser.runtime.onInstalled.addListener(installListener);

// On every startup download the diff(s)
browser.runtime.onStartup.addListener(startupListener);

// This is our request listener to start catching everything
browser.webRequest.onBeforeRequest.addListener(
	requestListener,
    // We intercept http too because if a website is enrolled but not TLS enabled we want to drop
	{ urls: ["http://*/*", "https://*/*"] },
	["blocking"]
);

browser.webRequest.onHeadersReceived.addListener(
    headersListener,
    // Here HTTP should no longer be a concern, we should have dropped the request before receiving headers anyway
    // However that would not be the case for .onion domains
    { urls: ["http://*/*", "https://*/*"] },
    // Do we want this to be "blocking"? If we detect an anomaly we should stop
    ["blocking", "responseHeaders"]
);


function installListener() {
    if (debug) {
        console.log("Extension installed");
    }
    // Initial list download here
    // We probably want do download the most recent list, verify signature and log inclusion
    // Then index persistently in indexeddb

};


function startupListener() {
    if (debug) {
        console.log("Started");
    }
    // Here we probably want to check for a diff update to the list
    // Stills needs to check signature and inclusion proof
    // But db update should be on average very very small
};


function tabCloseListener(tabId, removeInfo) {
    if (debug) {
        console.log(`Deleting metadata for tab ${tabId}`);
    }
    delete tabs[tabId];
}


async function headersListener(details) {
    // We checked for enrollment back when the request was fired
    if (tabs[details.tabId].is_enrolled === true) {
        if (details.type == "main_frame") {
            tabs[details.tabId].validcsp = false;
            tabs[details.tabId].sigstore_issuer = null;
            tabs[details.tabId].sigstore_identity = null;
            tabs[details.tabId].manifest = null;
            tabs[details.tabId].validmanifest = false;
            tabs[details.tabId].errors = [];
            
            var headers = [];

            details.responseHeaders.forEach(function(header) {
                headers.push(header["name"].toLowerCase());
                if (header["name"].toLowerCase() == "content-security-policy") {
                    tabs[details.tabId].validcsp = validateCSP(header["value"]);
                }
                if (header["name"].toLowerCase() == "x-sigstore-issuer") {
                    tabs[details.tabId].sigstore_issuer = header["value"];
                }
                if (header["name"].toLowerCase() == "x-sigstore-identity") {
                    tabs[details.tabId].sigstore_identity = header["value"];
                }
            });

            if (headers.length !== new Set(headers).size) {
                tabs[details.tabId].errors.push("Duplicate header keys found! EXIT!");
                return;
            }

            if (tabs[details.tabId].validcsp !== true) {
                tabs[details.tabId].errors.push("Invalid CSP! EXIT!");
                return;
            }

            if (tabs[details.tabId].sigstore_issuer === null || tabs[details.tabId].sigstore_identity === null) {
                tabs[details.tabId].errors.push("Failed to find both SigStore headers! EXIT!");
                return;
            }

            tabs[details.tabId].validpolicy = false;
            tabs[details.tabId].policy = `${tabs[details.tabId].sigstore_issuer}:${tabs[details.tabId].sigstore_identity}`;

            tabs[details.tabId].validpolicy = await validatePolicy(tabs[details.tabId].policy);

            if (tabs[details.tabId].validpolicy !== true) {
                tabs[details.tabId].errors.push("Invalid SigStore policy! EXIT!");
                return;
            }
            // By doing this here we gain a bit of async time: we start processing the request headers
            // while we download the manifest
            tabs[details.tabId].manifest_promise.then((response) => {
                if (response.ok !== true) {
                    tabs[details.tabId].errors.push("Failed to fetch manifest.json: server error");
                    return;
                }
                response.json().then((json) => {
                    tabs[details.tabId].manifest = json;
                    delete tabs[details.tabId].manifest_promise;
                }).catch((error) => {
                    tabs[details.tabId].errors.push(`Failed to parse manifest.json: ${error}`);
                    return;
                })
            }).catch((error) => {
                tabs[details.tabId].errors.push(`Failed to fetch manifest.json: ${error}`);
                return;
            });

            tabs[details.tabId].validmanifest = await validateManifest(tabs[details.tabId].manifest);
        }

        if (debug) {
            console.log(`Processed headers for ${details.url}`)
        }

        // We should also probably check that headers of non signed files
        // are not malicious (such as serving a png as js)
    }
};


async function requestListener(details) {
    //console.log(details);
    
    if (debug) {
        console.log(`${requestListener.name}: start`)
        console.log(details)
    }

    if (isExtensionRequest(details)) {
        // We will always wonder, is this check reasonable?
        if (debug) {
            console.log(`Skipping request interceptor for ${details.url}`);
        }
        return;
    }

    if (details.type == "main_frame") {
        tabs[details.tabId] = {};

        // Let's fail safe
        tabs[details.tabId].is_enrolled = true;
        tabs[details.tabId].fqdn = getFQDN(details.url);
        tabs[details.tabId].is_enrolled = await isFQDNEnrolled(tabs[details.tabId].fqdn);

        if (debug) {
            console.log(`${requestListener.name}:fqdn = ${tabs[details.tabId].fqdn}`);
            console.log(`${requestListener.name}:is_enrolled = ${tabs[details.tabId].is_enrolled}`);
        }

        // If the website is enrolled but is loading via HTTP abort anyway
        // Or maybe not if it's an onion website :)
        if (tabs[details.tabId].is_enrolled === true && isHTTPS(details.url) === false && isOnion(details.url) === false) {
            tabs[details.tabId].errors.push("Attempting to load HTTP resource for a non-onion enrolled FQDN! EXIT!")
        }

        // Do we care about this? What matters in the end is the main_frame context
        //if (tabs[details.tabId].is_enrolled === true && isRoot(details.url) === false) {
        //    tabs[details.tabId].errors.push("Attempting to load the application from a non-root path! EXIT!");
        //}

        // Fire manifest request in the background, but do not wait for it now
        if (tabs[details.tabId].is_enrolled === true) {
            // So, we cannot directly know that we are the initiator of this request, see
            // https://stackoverflow.com/questions/31129648/how-to-identify-who-initiated-the-http-request-in-firefox
            // It's tracked in the dev console, but no luck in extensions https://discourse.mozilla.org/t/access-webrequest-request-initiator-chain-stack-trace/75877
            // still we do not want to intercept this one :)
            // More sadness: https://stackoverflow.com/questions/47331875/webrequest-api-how-to-get-the-requestid-of-a-new-request
            tabs[details.tabId].manifest_promise = fetch(`https://${tabs[details.tabId].fqdn}/manifest.json`);
        }
    }

    // All this should happen only if the website is ultimately enrolled
    if (tabs[details.tabId].is_enrolled === true) {

        var filter = browser.webRequest.filterResponseData(details.requestId);

        if (debug) {
            console.log(`Processed request for ${details.url}`)
        }
        
        var source = [];
        filter.ondata = (event) => {
            // The data here is usually chunked; normally it would be streamed down as we get it
            // but since we can hash the content only at the end, we have to wait until we have everything
            // before deciding if the response content matches the manifest or not. So we are saving it and we will
            // build a blob later
            source.push(event.data);
        };

        filter.onstop = (event) => {
            if (debug) {
                console.log(`Processed response content for ${details.url}`);
            }

            if (isTabContextOK(tabs[details.tabId]) === true) {
                new Blob(source).arrayBuffer().then(function(blob) {
                    const pathname = new URL(details.url).pathname;
                    const manifest_hash = tabs[details.tabId].manifest[pathname];
                    SHA256(blob).then(function(content_hash) {
                        if (manifest_hash === arrayBufferToHex(content_hash)) {
                            if (debug) {
                                console.log(`Resource ${details.url} succesfully verified!`);
                            }
                            // If everything is OK then we can just write the raw blob back
                            filter.write(blob);
                        } else {
                            // This is just "DENIED" already encoded
                            // This fails just for the single file not in the manifest or with the wrong hash
                            console.log(`Error: hash mismatch for ${details.url} - expected: ${manifest_hash} - found: ${arrayBufferToHex(content_hash)}`);
                            filter.write(new Uint8Array([68, 69, 78, 73, 69, 68]));
                        }
                        // close() ensures that nothing can be added afterwards; disconnect() just stops the filter and not the response
                        // see https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/StreamFilter
                        filter.close();    
                    });
                });
            } else {
                // If headers are wrong we abort everything
                console.log(`Error: tab context is not valid ${details.url}`);
                filter.write(new Uint8Array([68, 69, 78, 73, 69, 68]));
                filter.close()
            }
        };
    }
}


function getFQDN(url) {
    const urlobj = new URL(url);
    return urlobj.hostname;
}


function isHTTPS(url) {
    const urlobj = new URL(url);
    if (urlobj.protocol === "https:") {
        return true;
    } else {
        return false;
    }
}


function isOnion(url) {
    const fqdn = getFQDN(url)
    return (fqdn.substring(fqdn.lastIndexOf('.')) === ".onion");
}


function isRoot(url) {
    const urlobj = new URL(url);
    return (urlobj.pathname === "/")
}


async function isFQDNEnrolled(fqdn) {
    const fqdn_hash = await SHA256(fqdn);
    //return fqdn_hash;
    if (fqdn === "nym.re" || fqdn === "lsd.cat") {
        return true;
    } else {
        return false;
    }
}


function isExtensionRequest(details) {
    return (details.originUrl !== undefined && details.documentUrl !== undefined && details.originUrl.substring(0, 16) === "moz-extension://" && details.documentUrl.substring(0, 16) === "moz-extension://" && details.tabId === -1);
}


async function SHA256(data) {
    // Sometimes we hash strings, such as the FQDN, sometimes we hash bytes, such as page content
    if (typeof(data) === "string") {
        var data = new TextEncoder('utf-8').encode(data);
    }
	var hash = await window.crypto.subtle.digest("SHA-256", data)

    return hash;
}


function validateCSP(csp) {
    // Here will go the CSP validator of the main_frame
    const res = parseContentSecurityPolicy(csp);
    return true;
}


async function validatePolicy(policy) {
    // Basic functionality is lookup the policy hash (with a single issuer and identity)
    var policy_hash = await SHA256(policy);
    // When we implement complex policies, we will need to normalize them first
    return true;
}

async function validateManifest(manifest) {
    return true;
}

// Ultimately, this silly function decides everything
function isTabContextOK(tab) {
    if (debug) {
        console.log(`For ${tab.fqdn}: validcsp = ${tab.validcsp}, validpolicy = ${tab.validpolicy}, validmanifest = ${tab.validmanifest}`);
    }
    if (tab.validcsp === true &&
        tab.validpolicy === true &&
        tab.validmanifest === true &&
        tab.errors.length === 0) {
        
        return true;
    } else {
        return false;
    }

}

function arrayBufferToHex(buffer) {
    var array = Array.from(new Uint8Array(buffer));
    return array.map((b) => b.toString(16).padStart(2, "0")).join("");
}


// CSP parser from https://github.com/helmetjs/content-security-policy-parser
const ASCII_WHITESPACE_CHARS = "\t\n\f\r ";
const ASCII_WHITESPACE = RegExp(`[${ASCII_WHITESPACE_CHARS}]+`);
const ASCII_WHITESPACE_AT_START = RegExp(`^[${ASCII_WHITESPACE_CHARS}]+`);
const ASCII_WHITESPACE_AT_END = RegExp(`[${ASCII_WHITESPACE_CHARS}]+$`);

// "An ASCII code point is a code point in the range U+0000 NULL to
// U+007F DELETE, inclusive." See <https://infra.spec.whatwg.org/#ascii-string>.
// deno-lint-ignore no-control-regex
const ASCII = /^[\x00-\x7f]*$/;

/**
 * Parse a serialized Content Security Policy via [the spec][0].
 *
 * [0]: https://w3c.github.io/webappsec-csp/#parse-serialized-policy
 *
 * @param policy The serialized Content Security Policy to parse.
 * @returns A Map of Content Security Policy directives.
 * @example
 * parseContentSecurityPolicy(
 *   "default-src 'self'; script-src 'unsafe-eval' scripts.example; object-src; style-src styles.example",
 * );
 * // => Map(4) {
 * //      "default-src" => ["'self'"],
 * //      "script-src" => ["'unsafe-eval'", "scripts.example"],
 * //      "object-src" => [],
 * //      "style-src" => ["styles.example"],
 * //    }
 */

function parseContentSecurityPolicy(policy) {

    const result = new Map();

    // "For each token returned by strictly splitting serialized on the
    // U+003B SEMICOLON character (;):"
    for (let token of policy.split(";")) {

        // "1. Strip leading and trailing ASCII whitespace from token."
        token = token
            .replace(ASCII_WHITESPACE_AT_START, "")
            .replace(ASCII_WHITESPACE_AT_END, "");

        // "2. If token is an empty string, or if token is not an ASCII string,
        //     continue."
        if (!token || !ASCII.test(token))
            continue;

        // We do these at the same time:
        // "3. Let directive name be the result of collecting a sequence of
        //     code points from token which are not ASCII whitespace."
        // "6. Let directive value be the result of splitting token on
        //     ASCII whitespace."
        const [rawDirectiveName, ...directiveValue] = token.split(ASCII_WHITESPACE);
        
        // "4. Set directive name to be the result of running ASCII lowercase on
        //     directive name."
        const directiveName = rawDirectiveName.toLowerCase();
        
        // "5. If policy's directive set contains a directive whose name is
        //     directive name, continue."
        if (result.has(directiveName))
            continue;

        // "7. Let directive be a new directive whose name is directive name, and
        //     value is directive value."
        // "8. Append directive to policy's directive set."
        result.set(directiveName, directiveValue);
    }
    return result;
}
