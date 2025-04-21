import { hexToUint8Array, stringToUint8Array } from "../sigstore/encoding";
import { origins } from "./../globals";
import { getHooks } from "./genhooks";
import {
  OriginStateFailed,
  OriginStateHolder,
  OriginStateInitial,
  OriginStatePopulatedManifest,
  OriginStateVerifiedManifest,
  OriginStateVerifiedPolicy,
} from "./interfaces/originstate";
import { PopupState } from "./interfaces/popupstate";
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

  // Step 2: Populate the required headers in the origin and check the policy
  if (originStateHolder.current.status === "request_sent") {
    originStateHolder.current = await (
      originStateHolder.current as OriginStateInitial
    ).verifyPolicy(normalizedHeaders);
    if (originStateHolder.current.status === "failed") {
      if (popupState) {
        popupState.valid_headers = false;
      }
      throw new Error(
        `Error validating headers: ${(originStateHolder.current as OriginStateFailed).errorMessage}`,
      );
    }

    if (popupState) {
      popupState.threshold = originStateHolder.current.policy?.threshold;
      popupState.valid_headers = true;
    }

    logger.addLog(
      "debug",
      "Header parsing complete",
      details.tabId,
      getFQDN(details.url),
    );

    // Step 3: Await the manifest request we fired on origin creation
    originStateHolder.current = await (
      originStateHolder.current as OriginStateVerifiedPolicy
    ).populateManifest();
    if (originStateHolder.current.status === "failed") {
      throw new Error(
        `Error populating manifest: ${(originStateHolder.current as OriginStateFailed).errorMessage}`,
      );
    }

    // Step 4: Validate the manifest
    originStateHolder.current = await (
      originStateHolder.current as OriginStatePopulatedManifest
    ).verifyManifest();
    if (originStateHolder.current.status === "failed") {
      if (popupState) {
        popupState.valid_manifest = false;
      }
      throw new Error(
        `Error validating manifest: ${(originStateHolder.current as OriginStateFailed).errorMessage}`,
      );
    }

    // Step 5: Ensure we are at the expected final state now
    if (originStateHolder.current.status !== "verified_manifest") {
      throw new Error(
        `Error with the origin state: expected origin to be in state verified_manifest, got ${originStateHolder.current.status}`,
      );
    }

    if (popupState) {
      popupState.valid_manifest = true;
      popupState.valid_signers = originStateHolder.current.valid_signers
        ? originStateHolder.current.valid_signers
        : [];
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

  const pathname = new URL(details.url).pathname;
  if (
    (originStateHolder.current as OriginStateVerifiedManifest).verifyCSP(
      csp,
      pathname,
    ) !== true
  ) {
    //console.log("CSP:", csp);
    //console.log("manifest:", originStateHolder.current.manifest.default_csp);
    throw new Error(`Failed to match CSP with manifest value for ${pathname}`);
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

  // TODO (performance): significant amount of time is spent calling this function
  // at every loaded file, without added benefit. It should be enough to call it if
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
    const originStateHolder = origins.get(getFQDN(details.url));

    if (
      !originStateHolder ||
      originStateHolder.current.status !== "verified_manifest" ||
      !(originStateHolder.current as OriginStateVerifiedManifest).manifest
    ) {
      deny(filter);
      filter.close();
      errorpage(details.tabId);
      throw new Error("Tab context is not valid");
    }

    const blob = await new Blob(source).arrayBuffer();
    const pathname = new URL(details.url).pathname;

    const manifest = (originStateHolder.current as OriginStateVerifiedManifest)
      .manifest;

    const manifest_hash =
      manifest.files[pathname] ||
      manifest.files[pathname.substring(0, pathname.lastIndexOf("/")) + "/"] ||
      manifest.files["/"];

    if (!manifest_hash) {
      deny(filter);
      filter.close();
      errorpage(details.tabId);
      throw new Error("Manifest does not contain a hash for the root.");
    }

    const content_hash = await SHA256(blob);
    // Sometimes answers gets cached and we get an empty result, we shouldn't mark those as a hash mismatch
    if (
      !arraysEqual(
        hexToUint8Array(manifest_hash),
        new Uint8Array(content_hash),
      ) &&
      blob.byteLength !== 0
    ) {
      if (details.type == "main_frame" && popupState) {
        popupState.valid_index = false;
      } else if (popupState) {
        popupState.invalid_assets.push(pathname);
      }
      deny(filter);
      filter.close();
      errorpage(details.tabId);
      throw new Error(
        `hash mismatch for ${details.url} - expected: ${manifest_hash} - found: ${arrayBufferToHex(content_hash)}`,
      );
    }
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
    // close() ensures that nothing can be added afterwards; disconnect() just stops the filter and not the response
    // see https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/StreamFilter
    filter.close();
    setOKIcon(details.tabId);
    // Redirect the main frame to an error page
  };
}
