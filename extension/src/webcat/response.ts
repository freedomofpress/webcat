import {
  BeforeRequestDetails,
  HeadersReceivedDetails,
} from "../browser/requests";
import { CacheKey } from "./cache";
import {
  base64UrlToUint8Array,
  stringToUint8Array,
  Uint8ArrayToBase64Url,
  Uint8ArrayToString,
} from "./encoding";
import { HookBuilder } from "./hookbuilder";
import { Enrollment, Manifest } from "./interfaces/bundle";
import { Database } from "./interfaces/database";
import { WebcatError, WebcatErrorCode } from "./interfaces/errors";
import {
  OriginState,
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

const WORKER_FETCH_DESTINATIONS = [
  "worker",
  "serviceworker",
  "sharedworker",
  "audioworklet",
  "paintworklet",
];

function assertVerifiedManifest(
  originState: OriginState,
): asserts originState is OriginStateVerifiedManifest {
  if (!originState.isManifestVerified()) {
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

export function isSafeRelativeLocation(value: string): boolean {
  value = value.trim();

  // No scheme, no protocol-relative, no backslashes
  return (
    (value.startsWith("/") ||
      value.startsWith("../") ||
      value.startsWith("./")) &&
    !value.startsWith("//") &&
    !value.includes("\\")
  );
}

export class ResponseValidator {
  // #marker is ephemeral, not persisted anywhere, but that's ok:
  // ResponseValidator attaches a StreamFilter that prevents the
  // background service worker from terminating while a response
  // is being processed
  readonly #marker = stringToUint8Array(
    `__WEBCAT_END__{${Uint8ArrayToBase64Url(crypto.getRandomValues(new Uint8Array(32)))}}\n`,
  );
  readonly #db: Database;
  readonly #hooks: HookBuilder;

  constructor(db: Database, hooks: HookBuilder) {
    this.#db = db;
    this.#hooks = hooks;
  }

  async validateHeaders(details: Stateful<HeadersReceivedDetails>) {
    if (!details.state.pendingOrigin) {
      throw new Error("missing pendingOrigin in request state");
    }
    // Some headers, such as CSP, needs to always be validated

    logger.info(`Validating response headers, url: ${details.url}`, details);

    // Step 1: Extract headers, normalize, check for duplicates and mandatory ones
    const result = this.extractAndValidateHeaders(details);

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
    if (details.state.pendingOrigin.isRequestSent()) {
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
        await details.state.pendingOrigin.verifyEnrollment(
          enrollment,
          delegation,
        );
      } else {
        await details.state.pendingOrigin.verifyEnrollment(
          undefined,
          delegation,
        );
      }

      if (details.state.pendingOrigin.isFailed()) {
        return details.state.pendingOrigin.error;
      }

      logger.debug("Header parsing complete", details);

      // Step 3: Populate and validate the manifest
      await details.state.pendingOrigin.verifyManifest();
      if (details.state.pendingOrigin.isFailed()) {
        return details.state.pendingOrigin.error;
      }

      // Step 4: Ensure we are at the expected final state now
      // This should never happen
      if (!details.state.pendingOrigin.isManifestVerified()) {
        throw new Error(
          `Error with the origin state: expected origin to be in state verified_manifest`,
        );
      }

      logger.info(`Metadata for ${details.url} loaded`, details);
    }

    // Now, we should have the manifest, and can validate the CSP based on path
    /* DEVELOPMENT GUARD */
    if (!details.state.pendingOrigin.isManifestVerified()) {
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
      isNewerSemver(version, details.state.pendingOrigin.manifest.version)
    ) {
      logger.info(
        `Detected new version ${version}, current_version ${details.state.pendingOrigin.manifest.version}`,
        details,
      );
      this.#db.origins.delete(
        CacheKey(details.state.fqdn, details.state.cachePartition),
      );
      // Mark the origin state so any sibling request that shares it won't
      // re-insert it via commitVerifiedOrigin later
      details.state.pendingOrigin.stale = true;
      await clearBrowserCaches([details.state.fqdn]);
      browser.tabs.reload(details.tabId);
    }

    const pathname = new URL(details.url).pathname;
    if (csp) {
      if (!details.state.pendingOrigin.verifyCSP(csp, pathname)) {
        return new WebcatError(WebcatErrorCode.CSP.MISMATCH, [
          String(pathname),
        ]);
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
      setOKIcon(details.tabId, details.state.pendingOrigin.delegation);
    }
  }

  extractAndValidateHeaders(
    details: Stateful<HeadersReceivedDetails>,
  ): Map<string, string> | WebcatError {
    // Ensure that response headers exist.
    if (!details.responseHeaders) {
      return new WebcatError(WebcatErrorCode.Headers.MISSING);
    }

    // Define the critical headers we care about.
    const criticalHeaders = new Set(["content-security-policy"]);

    const forbiddenHeaders = new Set([
      // See https://github.com/freedomofpress/webcat/issues/23
      // Furthermore, as reported by TBD there's the risk of TBD
      //"location",
      // See https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Refresh
      // It's just another way to achieve redirects
      "refresh",
      // See https://github.com/freedomofpress/webcat/issues/24
      "link",
    ]);

    // Track seen critical headers to detect duplicates.
    const seenCriticalHeaders = new Set<string>();
    const normalizedHeaders = new Map<string, string>();
    const headers: string[] = [];

    // Loop over each header, normalize the name, and store its value.
    for (const header of details.responseHeaders) {
      if (header.name && header.value) {
        const lowerName = header.name.toLowerCase();
        const value = header.value;

        // Check and block in case of forbidden headers
        // Location header: block entirely for sub-resources (redirects would
        // cause the resource to be matched against the destination path,
        // allowing a server to swap or reorder resources). Only main
        // navigations (main_frame / sub_frame) may use safe relative redirects.
        if (lowerName === "location") {
          if (!details.state.isFrame) {
            return new WebcatError(
              WebcatErrorCode.Headers.LOCATION_SUBRESOURCE,
              [String(value)],
            );
          }
          if (!isSafeRelativeLocation(value)) {
            return new WebcatError(WebcatErrorCode.Headers.LOCATION_EXTERNAL, [
              String(value),
            ]);
          }
        } else if (forbiddenHeaders.has(lowerName)) {
          return new WebcatError(WebcatErrorCode.Headers.FORBIDDEN, [
            String(lowerName),
          ]);
        }

        // Check for duplicates among critical headers.
        if (criticalHeaders.has(lowerName)) {
          if (seenCriticalHeaders.has(lowerName)) {
            return new WebcatError(WebcatErrorCode.Headers.DUPLICATE, [
              String(lowerName),
            ]);
          }
          seenCriticalHeaders.add(lowerName);
        }

        normalizedHeaders.set(lowerName, header.value);
        headers.push(lowerName);
      }
    }

    // Firefox may omit CSP from extension events for responses that are
    // satisfied by cache, including some 304 revalidation flows.
    if (details.fromCache !== true && details.statusCode !== 304) {
      // Ensure all critical headers are present.
      for (const criticalHeader of criticalHeaders) {
        if (!normalizedHeaders.has(criticalHeader)) {
          return new WebcatError(WebcatErrorCode.Headers.MISSING_CRITICAL, [
            String(criticalHeader),
          ]);
        }
      }
    }

    // Retrieve the Content-Security-Policy (CSP) header (safe to use non-null assertion here based on the check above).
    return normalizedHeaders;
  }

  async validateContent(details: Stateful<BeforeRequestDetails>) {
    function deny(filter: browser.webRequest.StreamFilter) {
      // DENIED
      filter.write(new Uint8Array([68, 69, 78, 73, 69, 68]));
    }

    const pathname = new URL(details.url).pathname;
    const originState = details.state.pendingOrigin;
    if (!originState) {
      throw new Error("missing pendingOrigin in request state");
    }

    let manifest!: Manifest;
    const filter = browser.webRequest.filterResponseData(details.requestId);
    const source: Promise<ArrayBuffer>[] = [];
    filter.onstart = () => {
      assertVerifiedManifest(originState);
      assertHeadersAvailable(details);
      manifest = originState.manifest;
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
              const hooks = this.#hooks.getPageHooks(
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
    let markerSeen = false;
    filter.ondata = (event: { data: ArrayBuffer }) => {
      // The data here is usually chunked; normally it would be streamed down as
      // we get it but since we can hash the content only at the end, we have to
      // wait until we have everything before deciding if the response content
      // matches the manifest or not. So we are saving it and we will build a
      // blob later. If the data is the marker, flush all buffered data;
      // anything received up to that point is from this or other extensions, not
      // the network.
      if (arraysEqual(this.#marker, new Uint8Array(event.data))) {
        source.forEach((hook) => {
          writeQueue = writeQueue.then(async () => filter.write(await hook));
        });
        source.length = 0;
        markerSeen = true;
      } else {
        source.push(Promise.resolve(event.data));
      }
    };

    filter.onstop = async () => {
      if (!markerSeen && !PASS_THROUGH_TYPES.has(details.type)) {
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
        setOKIcon(details.tabId, originState.delegation);
      }
      // Redirect the main frame to an error page
    };
  }

  markContent(details: HeadersReceivedDetails) {
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
      endMarkerInjector.write(this.#marker);
      endMarkerInjector.disconnect();
    };
  }
}
