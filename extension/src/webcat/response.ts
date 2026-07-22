import {
  BeforeRequestDetails,
  HeadersReceivedDetails,
} from "../browser/requests";
import { endMarker, origins } from "./../globals";
import { CacheKey } from "./cache";
import {
  base64UrlToUint8Array,
  stringToUint8Array,
  Uint8ArrayToBase64Url,
  Uint8ArrayToString,
} from "./encoding";
import { HookBuilder } from "./hookbuilder";
import { Enrollment, Manifest } from "./interfaces/bundle";
import { WebcatError, WebcatErrorCode } from "./interfaces/errors";
import {
  OriginStateFailed,
  OriginStateHolder,
  OriginStateInitial,
  OriginStateVerifiedEnrollment,
  OriginStateVerifiedManifest,
} from "./interfaces/originstate";
import { Stateful } from "./interfaces/requeststate";
import { logger } from "./logger";
import { PASS_THROUGH_TYPES } from "./resources";
import { errorpage, setOKIcon } from "./ui";
import {
  arraysEqual,
  clearBrowserCaches,
  isNewerSemver,
  SHA256,
} from "./utils";
import { extractAndValidateHeaders } from "./validators";

const WORKER_FETCH_DESTINATIONS = [
  "worker",
  "serviceworker",
  "sharedworker",
  "audioworklet",
  "paintworklet",
];

export async function validateResponseHeaders(
  details: Stateful<HeadersReceivedDetails>,
) {
  if (!details.state.pendingOrigin) {
    throw new Error("missing pendingOrigin in request state");
  }
  // Some headers, such as CSP, needs to always be validated

  logger.info(
    `Validating response headers, url: ${details.url} status: ${details.state.pendingOrigin.current.status}`,
    details,
  );

  // Step 1: Extract headers, normalize, check for duplicates and mandatory ones
  const result = extractAndValidateHeaders(details);

  if (result instanceof WebcatError) {
    return result; // or wrap it
  }

  // Otherwise it's the header map
  const normalizedHeaders = result;

  // Extract Content-Security-Policy. This may be missing on fully cached
  // responses (Firefox behavior), even if the policy is still applied.
  const csp = normalizedHeaders.get("content-security-policy");
  const version = normalizedHeaders.get("x-webcat-version");
  const delegation = normalizedHeaders.get("x-webcat-delegation");
  const enrollment_header = normalizedHeaders.get("x-webcat-enrollment");

  // Step 2: Populate the required headers in the origin and check the policy
  if (details.state.pendingOrigin.current.status === "request_sent") {
    // let's check for delegation and add it only when populating the orgin the first time

    // enrollment info can be bundled with the manifest or passed in header
    // when passed in headers we gain async time because enrollment validation
    // becomes nonblocking, while in the other case we have for the background fetch to wait
    let enrollment: Enrollment;
    if (enrollment_header) {
      try {
        enrollment = JSON.parse(
          Uint8ArrayToString(base64UrlToUint8Array(enrollment_header)),
        ) as Enrollment;
      } catch {
        return new WebcatError(WebcatErrorCode.Headers.ENROLLMENT_MALFORMED);
      }
      details.state.pendingOrigin.current = await (
        details.state.pendingOrigin.current as OriginStateInitial
      ).verifyEnrollment(enrollment, delegation);
    } else {
      details.state.pendingOrigin.current = await (
        details.state.pendingOrigin.current as OriginStateInitial
      ).verifyEnrollment(undefined, delegation);
    }

    if (details.state.pendingOrigin.current.status === "failed") {
      return (details.state.pendingOrigin.current as OriginStateFailed).error;
    }

    logger.debug("Header parsing complete", details);

    // Step 3: Populate and validate the manifest
    details.state.pendingOrigin.current = await (
      details.state.pendingOrigin.current as OriginStateVerifiedEnrollment
    ).verifyManifest();
    if (details.state.pendingOrigin.current.status === "failed") {
      return (details.state.pendingOrigin.current as OriginStateFailed).error;
    }

    // Step 4: Ensure we are at the expected final state now
    // This should never happen
    if (details.state.pendingOrigin.current.status !== "verified_manifest") {
      throw new Error(
        `Error with the origin state: expected origin to be in state verified_manifest, got ${details.state.pendingOrigin.current.status}`,
      );
    }

    logger.info(`Metadata for ${details.url} loaded`, details);
  }

  // Now, we should have the manifest, and can validate the CSP based on path
  /* DEVELOPMENT GUARD */
  if (
    !details.state.pendingOrigin.current.manifest ||
    details.state.pendingOrigin.current.status !== "verified_manifest"
  ) {
    // Though this should never happen?
    throw new Error(
      "Validating headers, but no valid manifest for the origin has been found.",
    );
  }
  /* END DEVELOPMENT GUARD */

  // We want the server to be able to tell clients that the webapp
  // has been updated and that users should update the manifest before loading
  if (
    version &&
    isNewerSemver(version, details.state.pendingOrigin.current.manifest.version)
  ) {
    logger.info(
      `Detected new version ${version}, current_version ${details.state.pendingOrigin.current.manifest.version}`,
      details,
    );
    origins.delete(CacheKey(details.state.fqdn, details.state.cachePartition));
    // Mark the holder so any sibling request that shares it won't re-insert
    // it via commitVerifiedOrigin later
    details.state.pendingOrigin.stale = true;
    await clearBrowserCaches([details.state.fqdn]);
    browser.tabs.reload(details.tabId);
  }

  const pathname = new URL(details.url).pathname;
  if (csp) {
    if (
      !(
        details.state.pendingOrigin.current as OriginStateVerifiedManifest
      ).verifyCSP(csp, pathname)
    ) {
      return new WebcatError(WebcatErrorCode.CSP.MISMATCH, [String(pathname)]);
    }

    logger.info(`CSP validated for path ${pathname}`, details);
  } else if (details.fromCache === true || details.statusCode === 304) {
    logger.debug(
      `Skipping CSP check for cached/304 response on path ${pathname}`,
      details,
    );
  } else {
    return new WebcatError(WebcatErrorCode.Headers.MISSING_CRITICAL, [
      "content-security-policy",
    ]);
  }

  // Step 5: If everything is fine, we can update the icon to the OK state
  // It's important not do do it for sub_frames, otherwise validating a subresource
  // would display as if the entire site was verified
  if (details.type === "main_frame") {
    setOKIcon(details.tabId, details.state.pendingOrigin.current.delegation);
  }
}

function assertVerifiedManifest(
  holder: OriginStateHolder,
): asserts holder is OriginStateHolder & {
  current: OriginStateVerifiedManifest;
} {
  if (
    holder.current.status !== "verified_manifest" ||
    !(holder.current as OriginStateVerifiedManifest).manifest
  ) {
    throw new Error("origin is not populated when it was expected");
  }
}

function assertHeadersAvailable<T>(
  details: BeforeRequestDetails & T,
): asserts details is HeadersReceivedDetails & T {
  if (!("responseHeaders" in details)) {
    throw new Error("response headers not available when expected");
  }
}

export async function validateResponseContent(
  details: Stateful<BeforeRequestDetails>,
  hookBuilder: HookBuilder,
) {
  function deny(filter: browser.webRequest.StreamFilter) {
    // DENIED
    filter.write(new Uint8Array([68, 69, 78, 73, 69, 68]));
  }

  const pathname = new URL(details.url).pathname;
  const originStateHolder = details.state.pendingOrigin;
  if (!originStateHolder) {
    throw new Error("missing pendingOrigin in request state");
  }

  let manifest!: Manifest;
  const filter = browser.webRequest.filterResponseData(details.requestId);
  const source: Promise<ArrayBuffer>[] = [];
  filter.onstart = () => {
    assertVerifiedManifest(originStateHolder);
    assertHeadersAvailable(details);
    manifest = originStateHolder.current.manifest;
    // If a pass-through media type isn't in the manifest, bail before receiving
    // any data so large files don't get buffered into the extension for nothing.
    if (
      !manifest.files[pathname] &&
      !(
        pathname.endsWith("/") &&
        manifest.files[pathname + manifest.default_index]
      ) &&
      PASS_THROUGH_TYPES.has(details.type)
    ) {
      filter.disconnect();
    }
    // Inject hooks to worker scripts
    if (details.type === "script" && details.requestHeaders) {
      for (const header of details.requestHeaders) {
        if (
          header.name.toLowerCase() === "sec-fetch-dest" &&
          header.value !== undefined
        ) {
          if (WORKER_FETCH_DESTINATIONS.includes(header.value)) {
            const hooks = hookBuilder.getPageHooks(
              manifest.wasm,
              details.state.cachePartition.firstParty,
              // Hooks are only injected to workers, and CSP restrictions only allow
              // same-origin workers, so the request's web origin is the URL's origin;
              // determine whether the URL is same-origin with the first party
              details.state.cachePartition.firstParty ===
                new URL(details.url).origin,
            );
            source.push(hooks.then((h) => stringToUint8Array(h).buffer));
          }
          break;
        }
      }
    }
  };

  let writeQueue: Promise<void> = Promise.resolve();
  let endMarkerSeen = false;
  filter.ondata = (event: { data: ArrayBuffer }) => {
    // The data here is usually chunked; normally it would be streamed down as
    // we get it but since we can hash the content only at the end, we have to
    // wait until we have everything before deciding if the response content
    // matches the manifest or not. So we are saving it and we will build a
    // blob later. If the data is the end marker, flush all buffered data;
    // anything received up to that point is from this or other extensions, not
    // the network.
    if (arraysEqual(endMarker, new Uint8Array(event.data))) {
      source.forEach((hook) => {
        writeQueue = writeQueue.then(async () => filter.write(await hook));
      });
      source.length = 0;
      endMarkerSeen = true;
    } else {
      source.push(Promise.resolve(event.data));
    }
  };

  filter.onstop = async () => {
    if (!endMarkerSeen && !PASS_THROUGH_TYPES.has(details.type)) {
      // The request terminated early, before headers were received,
      // possibly because the user navigated away. Close without
      // writing anything; don't display an error.
      filter.close();
      return;
    }
    try {
      // Make sure the response is complete and was not interrupted by a
      // network error; ignore incomplete responses without displaying an
      // error. When the request is not associated with a tab, skip the
      // check as a workaround to a bug in ServiceWorkers:
      // https://bugzilla.mozilla.org/show_bug.cgi?id=2054048
      if (details.tabId !== -1) {
        await details.completed;
      }
    } catch {
      logger.warn(`Request canceled, url: ${details.url}`, details);
      filter.close();
      return;
    }
    const blob = await new Blob(await Promise.all(source)).arrayBuffer();

    // Following order of priority:
    // - If there's an exact match, that should be the hash
    // - If the paths ends in /, and there was no exact match, then use default_index
    // - If everything else fails, it's an error or a catchall case, so attempt default_fallback
    let manifest_hash: string;

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
      errorpage(
        details,
        new WebcatError(WebcatErrorCode.File.MISSING, [pathname]),
      );
      return;
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
        details,
        new WebcatError(WebcatErrorCode.File.MISMATCH, [
          pathname,
          String(manifest_hash),
          String(Uint8ArrayToBase64Url(new Uint8Array(content_hash))),
        ]),
      );
      return;
    }

    // If everything is OK then we can just write the raw blob back
    logger.info(`${pathname} verified.`, details);

    await writeQueue;
    filter.write(blob);
    // close() ensures that nothing can be added afterwards; disconnect() just stops the filter and not the response
    // see https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/StreamFilter
    filter.close();
    if (details.type === "main_frame") {
      setOKIcon(details.tabId, originStateHolder.current.delegation);
    }
    // Redirect the main frame to an error page
  };
}

export function markResponseContent(
  details: browser.webRequest._OnHeadersReceivedDetails,
) {
  if (PASS_THROUGH_TYPES.has(details.type)) return;
  // Install a marking filter at the last possible moment: after
  // all extensions, including WEBCAT and NoScript, have injected their
  // hooks, but before receiving any code from the network
  const endMarkerInjector = browser.webRequest.filterResponseData(
    details.requestId,
  );
  endMarkerInjector.onstart = () => {
    // Inject the end marker, signaling the end of extension hooks and
    // the start of code that should be validated
    endMarkerInjector.write(endMarker);
    endMarkerInjector.disconnect();
  };
}
