import { origins } from "./../globals";
import {
  base64UrlToUint8Array,
  stringToUint8Array,
  Uint8ArrayToBase64Url,
  Uint8ArrayToString,
} from "./encoding";
import { getHooks } from "./genhooks";
import { Enrollment } from "./interfaces/bundle";
import { WebcatError, WebcatErrorCode } from "./interfaces/errors";
import {
  OriginStateFailed,
  OriginStateHolder,
  OriginStateInitial,
  OriginStateVerifiedEnrollment,
  OriginStateVerifiedManifest,
} from "./interfaces/originstate";
import { logger } from "./logger";
import { PASS_THROUGH_TYPES } from "./resources";
import { setOKIcon } from "./ui";
import { arraysEqual, errorpage, getFQDN, SHA256 } from "./utils";
import { extractAndValidateHeaders } from "./validators";

export async function validateResponseHeaders(
  originStateHolder: OriginStateHolder,
  details: browser.webRequest._OnHeadersReceivedDetails,
) {
  const fqdn = originStateHolder.current.fqdn;
  // Some headers, such as CSP, needs to always be validated

  logger.addLog(
    "info",
    `Validating response headers, url: ${details.url} status: ${originStateHolder.current.status}`,
    details.tabId,
    originStateHolder.current.fqdn,
  );

  // Step 1: Extract headers, normalize, check for duplicates and mandatory ones
  const result = extractAndValidateHeaders(details);

  if (result instanceof WebcatError) {
    return result; // or wrap it
  }

  // Otherwise it's the header map
  const normalizedHeaders = result;

  // The null assertion is checked in the loop above
  // Extract Content-Security-Policy
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const csp = normalizedHeaders.get("content-security-policy")!;

  // Step 2: Populate the required headers in the origin and check the policy
  if (originStateHolder.current.status === "request_sent") {
    // enrollment info can be bundled with the manifest or passed in header
    // when passed in headers we gain async time because enrollment validation
    // becomes nonblocking, while in the other case we have for the background fetch to wait
    const enrollment_header = normalizedHeaders.get("x-webcat-enrollment");
    let enrollment: Enrollment;
    if (enrollment_header) {
      try {
        enrollment = JSON.parse(
          Uint8ArrayToString(base64UrlToUint8Array(enrollment_header)),
        ) as Enrollment;
      } catch {
        return new WebcatError(WebcatErrorCode.Headers.ENROLLMENT_MALFORMED);
      }
      originStateHolder.current = await (
        originStateHolder.current as OriginStateInitial
      ).verifyEnrollment(enrollment);
    } else {
      originStateHolder.current = await (
        originStateHolder.current as OriginStateInitial
      ).verifyEnrollment();
    }

    if (originStateHolder.current.status === "failed") {
      return (originStateHolder.current as OriginStateFailed).error;
    }

    logger.addLog(
      "debug",
      "Header parsing complete",
      details.tabId,
      getFQDN(details.url),
    );

    // Step 3: Populate and validate the manifest
    originStateHolder.current = await (
      originStateHolder.current as OriginStateVerifiedEnrollment
    ).verifyManifest();
    if (originStateHolder.current.status === "failed") {
      return (originStateHolder.current as OriginStateFailed).error;
    }

    // Step 4: Ensure we are at the expected final state now
    // This should never happen
    if (originStateHolder.current.status !== "verified_manifest") {
      throw new Error(
        `Error with the origin state: expected origin to be in state verified_manifest, got ${originStateHolder.current.status}`,
      );
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
    throw new Error(
      "Validating CSP, but no valid manifest for the origin has been found.",
    );
  }
  /* END DEVELOPMENT GUARD */

  const pathname = new URL(details.url).pathname;
  if (
    !(originStateHolder.current as OriginStateVerifiedManifest).verifyCSP(
      csp,
      pathname,
    )
  ) {
    //console.log("CSP:", csp);
    //console.log("manifest:", originStateHolder.current.manifest.default_csp);
    return new WebcatError(WebcatErrorCode.CSP.MISMATCH, [String(pathname)]);
  }

  logger.addLog(
    "info",
    `CSP validated for path ${pathname}`,
    details.tabId,
    fqdn,
  );

  // TODO (performance): significant amount of time is spent calling this function
  // at every loaded file, without added benefit. It should be enough to call it if
  // details.type == "main_frame", but then the icon change does not work...
  setOKIcon(details.tabId);
}

function getVerifiedManifestState(fqdn: string): OriginStateHolder {
  const origin = origins.get(fqdn);
  if (
    !origin ||
    origin.current.status !== "verified_manifest" ||
    !(origin.current as OriginStateVerifiedManifest).manifest
  ) {
    throw new Error("origin is not populated when it was expected");
  }
  return origin as OriginStateHolder & {
    current: OriginStateVerifiedManifest;
  };
}

export async function validateResponseContent(
  details: browser.webRequest._OnBeforeRequestDetails,
) {
  function deny(filter: browser.webRequest.StreamFilter) {
    // DENIED
    filter.write(new Uint8Array([68, 69, 78, 73, 69, 68]));
  }

  const pathname = new URL(details.url).pathname;
  const fqdn = getFQDN(details.url);

  // The goal of doing this both here and after is the following: if a resource
  // is a media type and not in the manifest we do not want even to start filtering
  // otherwise large file might be loaded in memory by the extension without
  // then any real benefit
  if (details.type != "main_frame" && details.type != "sub_frame") {
    const originStateHolder = getVerifiedManifestState(fqdn);
    /* Development guard */
    // This should never happen! if we are here it means that a main or sub_frame is
    // loading a subresource, and thus origin must be populated!
    const manifest = (originStateHolder.current as OriginStateVerifiedManifest)
      .manifest;
    if (
      !manifest.files[pathname] &&
      !(
        pathname.endsWith("/") &&
        manifest.files[pathname + manifest.default_index]
      ) &&
      PASS_THROUGH_TYPES.has(details.type)
    ) {
      return {};
    }
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

  filter.onstop = async () => {
    const originStateHolder = getVerifiedManifestState(fqdn);
    const blob = await new Blob(source).arrayBuffer();

    const manifest = (originStateHolder.current as OriginStateVerifiedManifest)
      .manifest;

    // Following order of priority:
    // - If there's an exact match, that should be the hash
    // - If the paths ends in /, and there was no exact match, then use default_index
    // - If everything else fails, it's an error or a catchall case, so attempt default_fallback
    let manifest_hash: string;

    // TODO (default index should not have starting /), this is a quick patch for developing

    if (manifest.files[pathname]) {
      manifest_hash = manifest.files[pathname];
    } else if (pathname.endsWith("/")) {
      manifest_hash = manifest.files[pathname + manifest.default_index];
    } else {
      manifest_hash = manifest.files[manifest.default_fallback];
    }

    if (!manifest_hash) {
      deny(filter);
      filter.close();
      errorpage(details.tabId, new WebcatError(WebcatErrorCode.File.MISSING));
    }

    const content_hash = await SHA256(blob);
    // Sometimes answers gets cached and we get an empty result, we shouldn't mark those as a hash mismatch
    if (
      !arraysEqual(
        base64UrlToUint8Array(manifest_hash),
        new Uint8Array(content_hash),
      ) &&
      blob.byteLength !== 0
    ) {
      deny(filter);
      filter.close();
      errorpage(
        details.tabId,
        new WebcatError(WebcatErrorCode.File.MISMATCH, [
          String(manifest_hash),
          String(Uint8ArrayToBase64Url(new Uint8Array(content_hash))),
        ]),
      );
    }

    // If everything is OK then we can just write the raw blob back
    logger.addLog("info", `${pathname} verified.`, details.tabId, fqdn);

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
