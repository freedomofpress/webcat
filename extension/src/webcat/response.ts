import { OriginState } from "./interfaces";
import { validate, validateManifest } from "./validators";
import { parseSigners, parseThreshold } from "./parsers";
import { SHA256, arrayBufferToHex } from "./utils";
import { Sigstore } from "../sigstore/interfaces";
import { setOKIcon } from "./ui";

export async function validateResponseHeaders(
  sigstore: Sigstore,
  originState: OriginState,
  details: browser.webRequest._OnHeadersReceivedDetails,
) {
  const headers: string[] = [];

  // Some headers, such as CSP, needs to always be validated
  // Some others, like the policy, just when we load the manifest for the first time

  // In both cases, this should not happen
  if (!details.responseHeaders) {
    throw new Error("Missing response headers.");
  }

  /* Now, we should reload and reverify the manifest only if:
     1) It has not been done nefore
     2) TODO: The app has been updated --> not implemented
    */
  console.log(
    `Validating response headers, populated: ${originState.populated}`,
  );
  if (originState.populated === false) {

    for (const header of details.responseHeaders.sort()) {
      // This array is just used to detect duplicates
      headers.push(header["name"].toLowerCase());
      if (
        header["name"].toLowerCase() === "content-security-policy" &&
        header["value"]
      ) {
        originState.csp = header["value"];
      }

      // As we are iterating through the sorted array, signers should always come before threshold
      // Unless people did mixedcases... TODO
      if (
        header["name"].toLowerCase() == "x-sigstore-signers" &&
        header["value"]
      ) {
        originState.policy.signers = parseSigners(header["value"]);
      }

      if (
        header["name"].toLowerCase() == "x-sigstore-threshold" &&
        header["value"]
      ) {
        originState.policy.threshold = parseThreshold(
          header["value"],
          originState.policy.signers.size,
        );
      }
    }

    if (headers.length !== new Set(headers).size) {
      throw new Error("Duplicate header keys found!");
    }

    if (
      originState.policy.threshold < 1 ||
      originState.policy.signers.size < 1
    ) {
      throw new Error("Failed to find all the necessary policy headers!");
    }

    // TODO: free check if threshold > size(signers) then abort

    // TODO: here we validate that the hash in the preload lists matches the headers
    const hash = new Uint8Array();

    if ((await validate(originState.policy, originState.csp, hash)) !== true) {
      throw new Error("Response headers do not match the preload list.");
    }
    // By doing this here we gain a bit of async time: we start processing the request headers
    // while we download the manifest
    const manifestResponse = await originState.manifestPromise;

    if (manifestResponse.ok !== true) {
      throw new Error("Failed to fetch manifest.json: server error");
    }

    originState.manifest = await manifestResponse.json();

    originState.valid = await validateManifest(
      sigstore,
      originState.manifest,
      originState.policy,
    );

    if (!originState.valid) {
      throw new Error("Manifest signature verification failed.");
    }

    originState.populated = true;

    console.log(`Metadata for ${details.url} loaded`);
  } else {

    // CSP still needs to be evaluated every time
    let csp: string = "";
    for (const header of details.responseHeaders.sort()) {
      // This array is just used to detect duplicates
      headers.push(header["name"].toLowerCase());
      if (
        header["name"].toLowerCase() === "content-security-policy" &&
        header["value"]
      ) {
        csp = header["value"];
      }
    }

    if (headers.length !== new Set(headers).size) {
      throw new Error("Duplicate header keys found!");
    }

    if (csp !== originState.csp) {
      throw new Error("Response CSP does not match the verified one.");
    }
  }
  setOKIcon(details.tabId);
}

export async function validateResponseContent(
  originState: OriginState,
  details: browser.webRequest._OnBeforeRequestDetails,
) {
  function deny(filter: browser.webRequest.StreamFilter) {
    // DENIED
    filter.write(new Uint8Array([68, 69, 78, 73, 69, 68]));
  }

  const filter = browser.webRequest.filterResponseData(details.requestId);

  const source: ArrayBuffer[] = [];
  filter.ondata = (event: { data: ArrayBuffer }) => {
    // The data here is usually chunked; normally it would be streamed down as we get it
    // but since we can hash the content only at the end, we have to wait until we have everything
    // before deciding if the response content matches the manifest or not. So we are saving it and we will
    // build a blob later
    source.push(event.data);
  };

  filter.onstop = () => {
    if (originState.valid === true) {
      new Blob(source).arrayBuffer().then(function (blob) {
        var pathname = new URL(details.url).pathname;

        const manifest_hash = originState.manifest.manifest.files[pathname];

        if (typeof manifest_hash !== "string") {
          throw new Error(`File ${pathname} not found in manifest.`);
        }
        SHA256(blob).then(function (content_hash) {
          if (manifest_hash === arrayBufferToHex(content_hash)) {
            // If everything is OK then we can just write the raw blob back
            console.log(`${pathname} verified.`);
            filter.write(blob);
          } else {
            // This is just "DENIED" already encoded
            // This fails just for the single file not in the manifest or with the wrong hash
            console.log(
              `Error: hash mismatch for ${details.url} - expected: ${manifest_hash} - found: ${arrayBufferToHex(content_hash)}`,
            );
            deny(filter);
            browser.tabs.update(details.tabId, { url: browser.runtime.getURL("pages/error.html") });
          }
          // close() ensures that nothing can be added afterwards; disconnect() just stops the filter and not the response
          // see https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/StreamFilter
          filter.close();
          // Redirect the main frame to an error page
        });
      });
    } else {
      // If headers are wrong we abort everything
      console.log(`Error: tab context is not valid ${details.url}`);
      // DENIED
      deny(filter);
      filter.close();
      // Redirect the main frame to an error page
      browser.tabs.update(details.tabId, { url: browser.runtime.getURL("pages/error.html") });
    }
  };
}
