import { TabState } from './interfaces';
import { validateCSP, validatePolicy, validateManifest } from './validators';
import { parseSigners, parseThreshold } from './parsers';
import { isTabContextOK, SHA256, arrayBufferToHex } from './utils';

export async function validateResponseHeaders(tabState: TabState, details: browser.webRequest._OnHeadersReceivedDetails) {
    console.log(`Entering headers parsing for ${tabState.fqdn}`);
    if (details.type == "main_frame") {

        var headers: string[] = [];

        if (!details.responseHeaders) {
            throw new Error("Missing response headers.");
        }

        for (const header of details.responseHeaders.sort()) {
            headers.push(header["name"].toLowerCase());
            if (header["name"].toLowerCase() === "content-security-policy" && header["value"]) {
                tabState.validCSP = validateCSP(header["value"]);
            }
            // As we are iterating through the sorted array, signers should always come before threshold
            if (header["name"].toLowerCase() == "x-sigstore-signers" && header["value"]) {
                tabState.policy.signers = parseSigners(header["value"]);
            }
            if (header["name"].toLowerCase() == "x-sigstore-threshold" && header["value"]) {
                tabState.policy.threshold = parseThreshold(header["value"], tabState.policy.signers.size);
            }
        }

        if (headers.length !== new Set(headers).size) {
            throw new Error("Duplicate header keys found!");
        }

        if (tabState.validCSP !== true) {
            throw new Error("Invalid CSP!");
        }

        if (tabState.policy.threshold < 1 || tabState.policy.signers.size < 1) {
            throw new Error("Failed to find all the necessary policy headers!");
        }

        tabState.validPolicy = await validatePolicy(tabState.policy, tabState.policyHash);

        if (tabState.validPolicy !== true) {
            throw new Error("Invalid SigStore policy!");
        }
        // By doing this here we gain a bit of async time: we start processing the request headers
        // while we download the manifest
        const manifestResponse = await tabState.manifestPromise;
        
        if (manifestResponse.ok !== true) {
            throw new Error("Failed to fetch manifest.json: server error");
        }
        tabState.manifest = await manifestResponse.json()

        tabState.validManifest = await validateManifest(tabState.manifest);
    }

    // We should also probably check that headers of non signed files
    // are not malicious (such as serving a png as js)
}

export async function validateResponseContent(tabState: TabState, details: browser.webRequest._OnBeforeRequestDetails) {
    console.log(`Response checker: ${tabState.fqdn} is enrolled`);
    var filter = browser.webRequest.filterResponseData(details.requestId);
    
    var source: ArrayBuffer[] = [];
    filter.ondata = (event: { data: ArrayBuffer }) => {
        // The data here is usually chunked; normally it would be streamed down as we get it
        // but since we can hash the content only at the end, we have to wait until we have everything
        // before deciding if the response content matches the manifest or not. So we are saving it and we will
        // build a blob later
        source.push(event.data);
    };

    filter.onstop = (event) => {

        if (isTabContextOK(tabState) === true) {
            new Blob(source).arrayBuffer().then(function(blob) {
                const pathname = new URL(details.url).pathname;
                const manifest_hash = tabState.manifest.get(pathname);
                SHA256(blob).then(function(content_hash) {
                    if (manifest_hash === arrayBufferToHex(content_hash)) {

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
            // DENIED
            filter.write(new Uint8Array([68, 69, 78, 73, 69, 68]));
            filter.close()
        }
    };
}