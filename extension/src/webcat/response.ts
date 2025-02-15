import { hexToUint8Array, stringToUint8Array } from "../sigstore/encoding";
import { origins } from "./../globals";
import { getHooks } from "./genhooks";
import {
  OriginStateFailed,
  OriginStateHolder,
  OriginStateInitial,
  OriginStatePopulatedHeaders,
  OriginStatePopulatedManifest,
  OriginStateVerifiedManifest,
  PopupState,
} from "./interfaces";
import { logger } from "./logger";
import { setOKIcon } from "./ui";
import {
  arrayBufferToHex,
  arraysEqual,
  errorpage,
  getFQDN,
  SHA256,
} from "./utils";

export function extractAndValidateHeaders(
  details: browser.webRequest._OnHeadersReceivedDetails,
): Map<string, string> {
  // Ensure that response headers exist.
  if (!details.responseHeaders) {
    throw new Error("Missing response headers.");
  }

  // Define the critical headers we care about.
  const criticalHeaders = new Set([
    "content-security-policy",
    "x-sigstore-signers",
    "x-sigstore-threshold",
  ]);

  // Track seen critical headers to detect duplicates.
  const seenCriticalHeaders = new Set<string>();
  const normalizedHeaders = new Map<string, string>();
  const headers: string[] = [];

  // Loop over each header, normalize the name, and store its value.
  for (const header of details.responseHeaders) {
    if (header.name && header.value) {
      const lowerName = header.name.toLowerCase();

      // Check for duplicates among critical headers.
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

  // Ensure all critical headers are present.
  for (const criticalHeader of criticalHeaders) {
    if (!normalizedHeaders.has(criticalHeader)) {
      throw new Error(`Missing critical header: ${criticalHeader}`);
    }
  }

  // Retrieve the Content-Security-Policy (CSP) header (safe to use non-null assertion here based on the check above).
  return normalizedHeaders;
}

export async function validateResponseHeaders(
  originStateHolder: OriginStateHolder,
  popupState: PopupState | undefined,
  details: browser.webRequest._OnHeadersReceivedDetails,
) {
  const fqdn = originStateHolder.current.fqdn;
  // Some headers, such as CSP, needs to always be validated
  // Some others, like the policy, just when we load the manifest for the first time

  logger.addLog(
    "info",
    `Validating response headers, url: ${details.url} status: ${originStateHolder.current.status}`,
    details.tabId,
    originStateHolder.current.fqdn,
  );

  // Step 1: Extract headers, normalize, check for duplicates and mandatory ones
  let normalizedHeaders: Map<string, string>;
  try {
    normalizedHeaders = extractAndValidateHeaders(details);
  } catch (e) {
    if (popupState) {
      popupState.valid_headers = false;
    }
    throw new Error(`Error parsing headers: ${e}`);
  }

  // The null assertion is checked in the loop above
  // Extract Content-Security-Policy
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const csp = normalizedHeaders.get("content-security-policy")!;

  // TODO: once all of this is tested we can remove the temp variables and operate directly on the holder
  let populatedHeadersState: OriginStatePopulatedHeaders | OriginStateFailed;
  let populatedManifestState: OriginStatePopulatedManifest | OriginStateFailed;
  let verifiedManifestState: OriginStateVerifiedManifest | OriginStateFailed;

  // Step 2: If
  if (originStateHolder.current.status === "request_sent") {
    const initialState = originStateHolder.current as OriginStateInitial;
    populatedHeadersState =
      await initialState.populateHeaders(normalizedHeaders);
    if (populatedHeadersState.status === "failed") {
      if (popupState) {
        popupState.valid_headers = false;
      }
      throw new Error(
        `Error validating headers: ${populatedHeadersState.errorMessage}`,
      );
    }
    originStateHolder.current = populatedHeadersState;
    if (popupState) {
      popupState.threshold = originStateHolder.current.policy.threshold;
      popupState.valid_headers = true;
    }

    logger.addLog(
      "debug",
      "Header parsing complete",
      details.tabId,
      getFQDN(details.url),
    );

    populatedManifestState = await populatedHeadersState.populateManifest();
    if (populatedManifestState.status === "failed") {
      throw new Error(
        `Error populating manifest: ${populatedManifestState.errorMessage}`,
      );
    }

    originStateHolder.current = populatedManifestState;

    verifiedManifestState = await populatedManifestState.validateManifest();
    if (verifiedManifestState.status === "failed") {
      if (popupState) {
        popupState.valid_manifest = false;
      }
      throw new Error(
        `Error populating manifest: ${verifiedManifestState.errorMessage}`,
      );
    }

    originStateHolder.current = verifiedManifestState;

    if (originStateHolder.current.status !== "verified_manifest") {
      throw new Error(
        `FATAL: expect origin in state verified_manifest, got ${originStateHolder.current.status}`,
      );
    }

    if (popupState) {
      popupState.valid_manifest = true;
      popupState.valid_signers = originStateHolder.current.valid_signers;
    }

    logger.addLog(
      "info",
      `Metadata for ${details.url} loaded`,
      details.tabId,
      fqdn,
    );
  }

  // Now, we should have the manifest, and can validate the CSP based on path
  /* DEVELOPMENT GUARD */
  if (
    !originStateHolder.current.manifest ||
    originStateHolder.current.status !== "verified_manifest"
  ) {
    // Though this should never happen?
    if (popupState) {
      popupState.valid_manifest = true;
    }
    throw new Error(
      "Validating CSP, but no valid manifest for the origin has been found.",
    );
  }
  /* END DEVELOPMENT GUARD */

  const extraCSP = originStateHolder.current.manifest.extra_csp || {};
  const defaultCSP = originStateHolder.current.manifest.default_csp;

  const pathname = new URL(details.url).pathname;
  let correctCSP = "";

  // Sigh
  if (
    pathname === "/index.html" ||
    pathname === "/index.htm" ||
    pathname === "/"
  ) {
    correctCSP =
      extraCSP["/"] || extraCSP["/index.htm"] || extraCSP["/index.html"];
    logger.addLog(
      "debug",
      `CSP expecting ${correctCSP}, server returned ${csp}`,
      details.tabId,
      originStateHolder.current.fqdn,
    );
  }

  if (!correctCSP) {
    let bestMatch: string | null = null;
    let bestMatchLength = 0;

    for (const prefix in extraCSP) {
      if (
        prefix !== "/" &&
        pathname.startsWith(prefix) &&
        prefix.length > bestMatchLength
      ) {
        bestMatch = prefix;
        bestMatchLength = prefix.length;
      }
    }

    // Return the most specific match, or fallback to default CSP
    correctCSP = bestMatch ? extraCSP[bestMatch] : defaultCSP;
    logger.addLog(
      "debug",
      `CSP path best match is ${bestMatch ? bestMatch : "default_csp"} for ${pathname}, expecting ${correctCSP}, server returned ${csp}`,
      details.tabId,
      fqdn,
    );
  }

  if (csp !== correctCSP) {
    throw new Error(
      "Server returned CSP does not match the one defined in the manifest.",
    );
  }

  logger.addLog(
    "info",
    `CSP validated for path ${pathname}`,
    details.tabId,
    fqdn,
  );

  if (popupState) {
    popupState.valid_csp = true;
  }

  // TODO (perfomance): significant amount of time is spent calling this function
  // at every loadef ile, without added benefit. It should be enough to call it if
  // details.type == "main_frame", but then the icon change does not work...
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

  const fqdn = getFQDN(details.url);
  const filter = browser.webRequest.filterResponseData(details.requestId);

  const source: ArrayBuffer[] = [];
  filter.ondata = (event: { data: ArrayBuffer }) => {
    // The data here is usually chunked; normally it would be streamed down as we get it
    // but since we can hash the content only at the end, we have to wait until we have everything
    // before deciding if the response content matches the manifest or not. So we are saving it and we will
    // build a blob later
    source.push(event.data);
  };

  filter.onstop = async () => {
    if (!origins.has(fqdn)) {
      throw new Error(
        "The origin still does not exists while the response content is arriving.",
      );
    }
    const originStateHolder = origins.get(getFQDN(details.url));
    if (
      originStateHolder &&
      originStateHolder.current.status === "verified_manifest"
    ) {
      const blob = await new Blob(source).arrayBuffer();
      const pathname = new URL(details.url).pathname;

      const manifest = originStateHolder.current.manifest;
      if (!manifest) {
        throw new Error(
          "Manifest not loaded, and it should never happen here.",
        );
      }

      const manifest_hash =
        manifest.files[pathname] ||
        manifest.files[
          pathname.substring(0, pathname.lastIndexOf("/")) + "/"
        ] ||
        manifest.files["/"];

      if (!manifest_hash) {
        throw new Error("Manifest does not contain a hash for the root.");
      }

      //if (typeof manifest_hash !== "string") {
      //  throw new Error(`File ${pathname} not found in manifest.`);
      //}

      const content_hash = await SHA256(blob);
      // Sometimes answers gets cached and we get an empty result, we shouldnt mark those as a hash mismatch
      if (
        arraysEqual(
          hexToUint8Array(manifest_hash),
          new Uint8Array(content_hash),
        ) ||
        blob.byteLength === 0
      ) {
        // If everything is OK then we can just write the raw blob back
        logger.addLog("info", `${pathname} verified.`, details.tabId, fqdn);

        if (details.type == "main_frame" && popupState) {
          popupState.valid_index = true;
        } else if (popupState) {
          popupState.loaded_assets.push(pathname);
        }

        if (details.type === "script") {
          // Inject the WASM hooks in every loaded script.

          const hooks = getHooks(manifest.wasm);
          filter.write(stringToUint8Array(hooks));
        }

        filter.write(blob);
      } else {
        // This is just "DENIED" already encoded
        // This fails just for the single file not in the manifest or with the wrong hash
        logger.addLog(
          "error",
          `Error: hash mismatch for ${details.url} - expected: ${manifest_hash} - found: ${arrayBufferToHex(content_hash)}`,
          details.tabId,
          fqdn,
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
    } else {
      // If headers are wrong we abort everything
      logger.addLog(
        "error",
        `Error: tab context is not valid ${details.url}`,
        details.tabId,
        fqdn,
      );
      // DENIED
      deny(filter);
      filter.close();
      // Redirect the main frame to an error page
      errorpage(details.tabId);
    }
  };
}
