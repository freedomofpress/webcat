import { hexToUint8Array, Uint8ArrayToHex } from "../sigstore/encoding";
import { Sigstore } from "../sigstore/interfaces";
import { OriginState, PopupState } from "./interfaces";
import { origins } from "./listeners";
import { logger } from "./logger";
import { parseSigners, parseThreshold } from "./parsers";
import { setOKIcon } from "./ui";
import {
  arrayBufferToHex,
  arraysEqual,
  errorpage,
  getFQDN,
  SHA256,
} from "./utils";
import { validateCSP, validateManifest } from "./validators";

export async function validateResponseHeaders(
  sigstore: Sigstore,
  originState: OriginState,
  popupState: PopupState | undefined,
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
  logger.addLog(
    "info",
    `Validating response headers, url: ${details.url} populated: ${originState.populated}`,
    details.tabId,
    originState.fqdn,
  );
  if (originState.populated === false) {
    // Headers we care about (normalized to lowercase)
    const criticalHeaders = new Set([
      "content-security-policy",
      "x-sigstore-signers",
      "x-sigstore-threshold",
    ]);

    // Track seen critical headers to detect duplicates
    const seenCriticalHeaders = new Set<string>();
    const normalizedHeaders = new Map<string, string>();

    for (const header of details.responseHeaders) {
      if (header.name && header.value) {
        const lowerName = header.name.toLowerCase();

        // Check for duplicates only among critical headers
        if (criticalHeaders.has(lowerName)) {
          if (seenCriticalHeaders.has(lowerName)) {
            throw new Error(`Duplicate critical header detected: ${lowerName}`);
          }
          seenCriticalHeaders.add(lowerName);
        }

        normalizedHeaders.set(lowerName, header.value);
        headers.push(lowerName);
      }
    }

    // Extract Content-Security-Policy
    if (normalizedHeaders.has("content-security-policy")) {
      originState.csp = normalizedHeaders.get("content-security-policy")!;
    }

    // Extract X-Sigstore-Signers
    if (normalizedHeaders.has("x-sigstore-signers")) {
      const signersHeader = normalizedHeaders.get("x-sigstore-signers")!;
      originState.policy.signers = parseSigners(signersHeader);
    }

    // Extract X-Sigstore-Threshold
    if (normalizedHeaders.has("x-sigstore-threshold")) {
      const thresholdHeader = normalizedHeaders.get("x-sigstore-threshold")!;
      originState.policy.threshold = parseThreshold(
        thresholdHeader,
        originState.policy.signers.size,
      );

      // Update popup state if it exists
      if (popupState) {
        popupState.threshold = originState.policy.threshold;
      }
    }

    if (
      originState.policy.threshold < 1 ||
      originState.policy.signers.size < 1 ||
      originState.policy.threshold > originState.policy.signers.size
    ) {
      throw new Error("Failed to find all the necessary policy headers!");
    }

    originState.valid_csp = await validateCSP(
      originState.csp,
      originState.fqdn,
      details.tabId,
    );

    if (originState.valid_csp !== true) {
      throw new Error("CSP provided by the server has non allowed directives!");
    }

    const cspRules = originState.csp
      .split(";")
      .map((rule) => rule.trim().toLowerCase())
      .filter((rule) => rule.length > 0);
    cspRules.sort();
    const normalizedCsp = cspRules.join("; ");

    const normalizedSigners = Array.from(originState.policy.signers).map(
      ([issuer, identity]) => ({
        identity,
        issuer,
      }),
    );

    // Sort the normalized signers by identity, then issuer
    normalizedSigners.sort(
      (a, b) =>
        a.identity.localeCompare(b.identity) ||
        a.issuer.localeCompare(b.issuer),
    );

    // Create the policy object
    const policyObject = {
      "x-sigstore-signers": normalizedSigners, // Use array of objects
      "x-sigstore-threshold": originState.policy.threshold, // Already normalized
      "content-security-policy": normalizedCsp,
    };

    // Compute hash of the normalized policy
    const policyString = JSON.stringify(policyObject);
    logger.addLog(
      "info",
      `policy: ${policyString}`,
      details.tabId,
      originState.fqdn,
    );

    // Validate policy hash
    logger.addLog(
      "info",
      `Computed policy hash is ${Uint8ArrayToHex(new Uint8Array(await SHA256(policyString)))}`,
      details.tabId,
      originState.fqdn,
    );
    if (
      !arraysEqual(
        originState.policyHash,
        new Uint8Array(await SHA256(policyString)),
      )
    ) {
      throw new Error("Response headers do not match the preload list.");
    }

    logger.addLog(
      "debug",
      "Header parsing complete",
      details.tabId,
      getFQDN(details.url),
    );

    // By doing this here we gain a bit of async time: we start processing the request headers
    // while we download the manifest
    const manifestResponse = await originState.manifestPromise;

    logger.addLog(
      "debug",
      "Manifest request returned",
      details.tabId,
      getFQDN(details.url),
    );

    if (manifestResponse.ok !== true) {
      throw new Error("Failed to fetch manifest.json: server error");
    }

    if (popupState) {
      popupState.valid_headers = true;
    }

    originState.manifest = await manifestResponse.json();

    originState.valid = await validateManifest(
      sigstore,
      originState,
      details.tabId,
      popupState,
    );

    if (!originState.valid) {
      if (popupState) {
        popupState.valid_manifest = false;
      }
      throw new Error("Manifest signature verification failed.");
    }

    if (popupState) {
      popupState.valid_manifest = true;
    }

    originState.populated = true;

    logger.addLog(
      "info",
      `Metadata for ${details.url} loaded`,
      details.tabId,
      originState.fqdn,
    );
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

    if (popupState) {
      popupState.valid_headers = true;
    }
  }
  setOKIcon(details.tabId);
}

export async function validateResponseContent(
  popupState: PopupState | undefined,
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
    if (!origins.has(getFQDN(details.url))) {
      throw new Error(
        "The origin still does not exists while the response content is arriving.",
      );
    }
    const originState = origins.get(getFQDN(details.url))!;
    if (originState.valid === true) {
      new Blob(source).arrayBuffer().then(function (blob) {
        const pathname = new URL(details.url).pathname;

        if (!originState.manifest) {
          throw new Error(
            "Manifest not loaded, and it should never happen here.",
          );
        }

        const manifest_hash =
          originState.manifest.manifest.files[pathname] ||
          originState.manifest.manifest.files["/"];

        if (!manifest_hash) {
          throw new Error("Manifest does not contain a hash for the root.");
        }

        //if (typeof manifest_hash !== "string") {
        //  throw new Error(`File ${pathname} not found in manifest.`);
        //}

        SHA256(blob).then(function (content_hash) {
          if (
            arraysEqual(
              hexToUint8Array(manifest_hash),
              new Uint8Array(content_hash),
            )
          ) {
            // If everything is OK then we can just write the raw blob back
            logger.addLog(
              "info",
              `${pathname} verified.`,
              details.tabId,
              originState.fqdn,
            );

            if (details.type == "main_frame" && popupState) {
              popupState.valid_index = true;
            } else if (popupState) {
              popupState.loaded_assets.push(pathname);
            }

            filter.write(blob);
          } else {
            // This is just "DENIED" already encoded
            // This fails just for the single file not in the manifest or with the wrong hash
            logger.addLog(
              "error",
              `Error: hash mismatch for ${details.url} - expected: ${manifest_hash} - found: ${arrayBufferToHex(content_hash)}`,
              details.tabId,
              originState.fqdn,
            );
            if (details.type == "main_frame" && popupState) {
              popupState.valid_index = false;
            } else if (popupState) {
              popupState.invalid_assets.push(pathname);
            }
            deny(filter);
            errorpage(details.tabId);
          }
          // close() ensures that nothing can be added afterwards; disconnect() just stops the filter and not the response
          // see https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/StreamFilter
          filter.close();
          // Redirect the main frame to an error page
        });
      });
    } else {
      // If headers are wrong we abort everything
      logger.addLog(
        "error",
        `Error: tab context is not valid ${details.url}`,
        details.tabId,
        originState.fqdn,
      );
      // DENIED
      deny(filter);
      filter.close();
      // Redirect the main frame to an error page
      errorpage(details.tabId);
    }
  };
}
