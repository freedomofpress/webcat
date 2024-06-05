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

// On first extension install download and verify a full list
browser.runtime.onInstalled.addListener(installListener);

// On every startup download the diff(s)
browser.runtime.onStartup.addListener(startupListener);

// This is our request listener to start catching everything
browser.webRequest.onBeforeRequest.addListener(
	requestListener,
    // We intercept http too because if a website is enrolled but not TLS enabled we want to drop and run
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
    console.log("Installed");
    // Initial list download here
    // We probably want do download the most recent list, verify signature and log inclusion
    // Then index persistently in indexeddb

};

function startupListener() {
    console.log("Started");
    // Here we probably want to check for a diff update to the list
    // Stills needs to check signature and inclusion proof
    // But db update should be on average very very small
};

async function headersListener(details) {
    //console.log(details);

    if (isExtensionRequest(details)) {
        // We will always wonder, is this check reasonable?
        if (debug) {
            console.log(`Skipping headers interceptor for ${details.url}`);
        }
        return;
     }

    if (details.type == "main_frame") {
        const tab_id = details.tabId
        var validcsp = false;
        var sigstore_issuer = null;
        var sigstore_identity = null;
        var headers = [];

        details.responseHeaders.forEach(function(header) {
            headers.push(header["name"].toLowerCase());
            if (header["name"].toLowerCase() == "content-security-policy") {
                validcsp = validateCSP(header["value"]);
            }
            if (header["name"].toLowerCase() == "x-sigstore-issuer") {
                sigstore_issuer = header["value"];
            }
            if (header["name"].toLowerCase() == "x-sigstore-identity") {
                sigstore_identity = header["value"];
            }
        });

        if (headers.length !== new Set(headers).size) {
            console.log("Duplicate header keys found! EXIT!");
        }

        if (validcsp !== true) {
            console.log("Invalid CSP! EXIT!");
        }

        if (sigstore_issuer === null || sigstore_identity === null) {
            console.log("Failed to find both SigStore headers! EXIT!");
        }

        var validpolicy = false;
        var policy = `${sigstore_issuer}:${sigstore_identity}`;
        
        validpolicy = await validatePolicy(policy);

        if (validpolicy !== true) {
            console.log("Invalid SigStore policy! EXIT!");
        }
    }

    if (debug) {
        console.log(`[2] Processed headers for ${details.url}`)
    }
    // Here we check for headers of the main frame:
    // Sigstore headers and CSP mostly
    // We should also probably check that headers of non signed files
    // are not malicious (such as serving a png as js)
};

async function requestListener(details) {
    
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
        var is_enrolled = false;
        const fqdn = getFQDN(details.url);
        is_enrolled = await isFQDNEnrolled(fqdn);

        if (debug) {
            console.log(`${requestListener.name}:fqdn = ${fqdn}`);
            console.log(`${requestListener.name}:is_enrolled = ${is_enrolled}`);
        }

        // If the website is enrolled but is loading via HTTP abort anyway
        // Or maybe not if it's an onion website :)
        if (is_enrolled === true && isHTTPS(details.url) === false && isOnion(details.url) === false) {
            console.log("Attempting to load HTTP resource for a non-onion enrolled FQDN! EXIT!")
        }

        if (is_enrolled === true && isRoot(details.url) === false) {
            console.log("Attempting to load the application from a non-root path! EXIT!");
        }

        // Fire manifest request in the background, but do not wait for it now
        if (is_enrolled === true) {
            // So, we cannot directly know that we are the initiator of this request, see
            // https://stackoverflow.com/questions/31129648/how-to-identify-who-initiated-the-http-request-in-firefox
            // It's tracked in the dev console, but no luck in extensions https://discourse.mozilla.org/t/access-webrequest-request-initiator-chain-stack-trace/75877
            // still we do not want to intercept this one :)
            // More sadness: https://stackoverflow.com/questions/47331875/webrequest-api-how-to-get-the-requestid-of-a-new-request
            var manifest = fetch(`https://${fqdn}/manifest.json`);
        }
    }

    var filter = browser.webRequest.filterResponseData(details.requestId);

    if (debug) {
        console.log(`[1] Processed request for ${details.url}`)
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
            console.log(`[3] Processed response content for ${details.url}`);
        }
        new Blob(source).arrayBuffer().then(function(blob) {
            var manifest_hash = new ArrayBuffer(32); 
            SHA256(blob).then(function(content_hash) {
                if (manifest_hash === content_hash) {
                    if (debug) {
                        console.log(`Resource ${details.url} succesfully verified!`);
                    }
                    // If everything is OK then we can just write the raw blob back
                    filter.write(blob);
                } else {
                    // This is just "DENIED" already encoded
                    console.log(`Error: hash mismatch for ${details.url} - expected: ${arrayBufferToHex(manifest_hash)} - found: ${arrayBufferToHex(content_hash)}`);
                    filter.write(new Uint8Array([ 68, 69, 78, 73, 69, 68 ]));
                }
                // close() ensures that nothing can be added afterwards; disconnect() just stops the filter and not the response
                // see https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/StreamFilter
                filter.close();    
            });
        });
    };
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
    const fqdn_hash = SHA256(fqdn);
    //return fqdn_hash;
    if (fqdn == "test1.local" || fqdn == "test2.local") {
        return true;
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
    return true;
}

async function validatePolicy(policy) {
    // Basic functionality is lookup the policy hash (with a single issuer and identity)
    var policy_hash = await SHA256(policy);
    // When we implement complex policies, we will need to normalize them first
    return true;
}

function arrayBufferToHex(buffer) {
    var array = Array.from(new Uint8Array(buffer));
    return array.map((b) => b.toString(16).padStart(2, "0")).join("");
}
