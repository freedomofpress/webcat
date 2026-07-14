import { endpoint } from "../config";
import { CachePartition, db, origins, requestInfo, tabs } from "../globals";
import { CacheKey } from "./cache";
import type { WebcatDatabase } from "./db";
import { getHooks } from "./genhooks";
import { hooksType, metadataRequestSource } from "./interfaces/base";
import { WebcatError } from "./interfaces/errors";
import {
  OriginStateHolder,
  OriginStateVerifiedManifest,
} from "./interfaces/originstate";
import { logger } from "./logger";
import { validateOrigin } from "./request";
import { FRAME_TYPES } from "./resources";
import {
  hookResponseContent,
  markResponseContent,
  validateResponseContent,
  validateResponseHeaders,
} from "./response";
import { errorpage } from "./ui";
import { retryUpdateIfFailed } from "./update";
import {
  clearBrowserCaches,
  getFirstParty,
  getFQDN,
  isExtensionRequest,
  isNewerSemver,
} from "./utils";

function commitVerifiedOrigin(
  fqdn: string,
  holder: OriginStateHolder,
  cachePartition: CachePartition,
): void {
  if (holder.stale) {
    return;
  }
  if (holder.current.status !== "verified_manifest") {
    return;
  }
  const incoming = (holder.current as OriginStateVerifiedManifest).manifest
    .version;
  const existing = origins.get(CacheKey(fqdn, cachePartition));
  if (existing && existing.current.status === "verified_manifest") {
    const current = (existing.current as OriginStateVerifiedManifest).manifest
      .version;
    if (!isNewerSemver(incoming, current)) {
      return;
    }
  }
  origins.set(CacheKey(fqdn, cachePartition), holder);
}

export async function installListener() {
  console.log("[webcat] Running installListener");
  // Startupinstall logic is in globals.ts on the main thread
  // TBB/incognito window only mode don't seem to call these listeners
}

export async function startupListener() {
  console.log("[webcat] Running startupListener");
  // Startupinstall logic is in globals.ts on the main thread
  // TBB/incognito window only mode don't seem to call these listeners
}

export async function headersListener(
  details: browser.webRequest._OnHeadersReceivedDetails,
): Promise<browser.webRequest.BlockingResponse> {
  const fqdn = getFQDN(details.url);
  const info = requestInfo.get(details.requestId);

  // Skip non-enrolled and extension requests
  if (!info || isExtensionRequest(details)) {
    return {};
  }

  const { pendingOrigin: originStateHolder, cachePartition } = info;

  if (!originStateHolder) {
    throw new Error("No originState while starting to parse response.");
  }

  const result = await validateResponseHeaders(
    originStateHolder,
    details,
    cachePartition,
  );
  if (result instanceof WebcatError) {
    logger.addLog(
      "error",
      `Error when parsing response headers: ${result}: ${result.details?.join(", ")}`,
      details.tabId,
      fqdn,
    );
    requestInfo.delete(details.requestId);
    tabs.delete(details.tabId);
    errorpage(details.tabId, fqdn, result, !FRAME_TYPES.includes(details.type));
    return { cancel: true };
  }

  commitVerifiedOrigin(fqdn, originStateHolder, cachePartition);
  requestInfo.delete(details.requestId);

  markResponseContent(details);

  // Here we must have already validated the enrollment and the manifest
  // and thus should have all the information, but we haven't started
  // sending data back, so it's a good time to register a listener since
  // we cannot inject yet. if the state of the tab is not yet "OnCommitted"
  // injecting the content_script fails silently

  // We thus want to inject as soon as the context is ready fro injection,
  // but not before. Since we repeat this procedure each navigation to an
  // enrolled main_frame, we want a one shot self deleting listener. The listener
  // has to be redefined each time, otherwise if it was a global function
  // Firefox would not re-record it

  // Also, we want to target the correct frame for the following cases:
  // - if a sub_frame is enrolled, but the main_frame not, we should only inject in the sub_frame
  // - if a main_frame is enrolled, it could contain frames from other enrolled origins
  //   and those would have different hooks with their own wasm allowlist
  // - a an enrolled main_frame might contain non enrolled sub_frames, and those should not receive any hooks
  //   (currently this is forbidden, but might change in the future)

  if (
    FRAME_TYPES.includes(details.type) &&
    originStateHolder.current.manifest
  ) {
    const wasm = originStateHolder.current.manifest.wasm;

    const listener = async (
      navDetails: browser.webNavigation._OnDOMContentLoadedDetails,
    ) => {
      if (navDetails.tabId !== details.tabId) return;
      if (navDetails.frameId !== details.frameId) return;

      browser.webNavigation.onDOMContentLoaded.removeListener(listener);

      await browser.tabs.executeScript(details.tabId, {
        code: await getHooks(
          hooksType.content_script,
          wasm,
          cachePartition.firstParty,
          cachePartition.firstParty === new URL(details.url).origin,
        ),
        runAt: "document_start",
        frameId: details.frameId,
      });
    };

    browser.webNavigation.onDOMContentLoaded.addListener(listener);
  }

  return {};
}

export async function beforeHeadersListener(
  details: browser.webRequest._OnBeforeSendHeadersDetails,
): Promise<browser.webRequest.BlockingResponse> {
  // this listener is only added for script requests, i.e.
  // here we already know details.type === "script"
  if (!details.requestHeaders) {
    console.error("FATAL: request headers not available");
    return { cancel: true };
  }
  for (const header of details.requestHeaders) {
    if (header.name.toLowerCase() === "sec-fetch-dest") {
      switch (header.value) {
        case "worker":
        case "serviceworker":
        case "sharedworker":
        case "audioworklet":
        case "paintworklet":
          hookResponseContent(details);
      }
      break;
    }
  }
  return {};
}

export async function requestListener(
  details: browser.webRequest._OnBeforeRequestDetails,
): Promise<browser.webRequest.BlockingResponse> {
  if (isExtensionRequest(details)) {
    return {};
  }

  const fqdn = getFQDN(details.url);
  const cachePartition = {
    firstParty: await getFirstParty(details),
    incognito: !!details.incognito,
  };

  const isFrame = FRAME_TYPES.includes(details.type);

  // Frame-only pre-setup: retry pending list updates
  if (isFrame) {
    logger.addLog(
      "info",
      `Loading ${details.type} ${details.url}`,
      details.tabId,
      fqdn,
    );
    await retryUpdateIfFailed(db, endpoint);
  }

  let originStateHolder: OriginStateHolder | undefined;
  if (!isFrame) {
    originStateHolder = origins.get(CacheKey(fqdn, cachePartition));
    if (originStateHolder) {
      requestInfo.set(details.requestId, {
        pendingOrigin: originStateHolder,
        cachePartition,
      });
    }
  }

  if (!originStateHolder) {
    const result = await validateOrigin(
      fqdn,
      details.url,
      details.tabId,
      isFrame
        ? metadataRequestSource.main_frame
        : metadataRequestSource.sub_resource,
      details.requestId,
      cachePartition,
    );
    if (result instanceof WebcatError) {
      requestInfo.delete(details.requestId);
      if (isFrame) {
        tabs.delete(details.tabId);
        errorpage(details.tabId, fqdn, result, !isFrame);
      }
      return { cancel: true };
    }
    if (result) {
      // HTTPS redirect; browser reissues under a fresh requestId.
      if (isFrame) {
        logger.addLog("info", `Redirecting to https`, details.tabId, fqdn);
      }
      return result;
    }
    originStateHolder = requestInfo.get(details.requestId)?.pendingOrigin;
  }

  // No holder means the fqdn isn't enrolled
  if (!originStateHolder) {
    return {};
  }

  await validateResponseContent(details, originStateHolder, cachePartition);
  return {};
}

// Ensure pending objects do not leak
function errorOccurredListener(
  details: browser.webRequest._OnErrorOccurredDetails,
): void {
  requestInfo.delete(details.requestId);
}

function completedListener(
  details: browser.webRequest._OnCompletedDetails,
): void {
  requestInfo.delete(details.requestId);
}

// Single global webRequest listener registration that scopes to the union
// of currently enrolled FQDNs. We re-register the listeners on every list
// update; we always add the new listener before removing the old one, so
// there is no window with no listener.
type RegisteredListeners = {
  before?: (
    details: browser.webRequest._OnBeforeRequestDetails,
  ) => Promise<browser.webRequest.BlockingResponse>;
  beforeHeaders?: (
    details: browser.webRequest._OnBeforeSendHeadersDetails,
  ) => Promise<browser.webRequest.BlockingResponse>;
  headers?: (
    details: browser.webRequest._OnHeadersReceivedDetails,
  ) => Promise<browser.webRequest.BlockingResponse>;
  errorOccurred?: (details: browser.webRequest._OnErrorOccurredDetails) => void;
  completed?: (details: browser.webRequest._OnCompletedDetails) => void;
};

let currentListeners: RegisteredListeners = {};

function buildUrlPatterns(fqdns: string[]): string[] {
  const urls: string[] = [];
  for (const fqdn of fqdns) {
    urls.push(`http://${fqdn}/*`);
    urls.push(`https://${fqdn}/*`);
  }
  return urls;
}

function removeListeners(listeners: RegisteredListeners): void {
  if (listeners.before) {
    browser.webRequest.onBeforeRequest.removeListener(listeners.before);
  }
  if (listeners.beforeHeaders) {
    browser.webRequest.onBeforeSendHeaders.removeListener(
      listeners.beforeHeaders,
    );
  }
  if (listeners.headers) {
    browser.webRequest.onHeadersReceived.removeListener(listeners.headers);
  }
  if (listeners.errorOccurred) {
    browser.webRequest.onErrorOccurred.removeListener(listeners.errorOccurred);
  }
  if (listeners.completed) {
    browser.webRequest.onCompleted.removeListener(listeners.completed);
  }
}

export async function installEnrolledListeners(
  database: WebcatDatabase,
): Promise<void> {
  let fqdns: string[];
  try {
    fqdns = await database.listAllFQDNs();
  } catch (error) {
    console.error("[webcat] listAllFQDNs failed:", error);
    return;
  }

  const urls = buildUrlPatterns(fqdns);

  // The registration needs to be different from the existing one
  const before = (details: browser.webRequest._OnBeforeRequestDetails) =>
    requestListener(details);
  const beforeHeaders = (
    details: browser.webRequest._OnBeforeSendHeadersDetails,
  ) => beforeHeadersListener(details);
  const headers = (details: browser.webRequest._OnHeadersReceivedDetails) =>
    headersListener(details);
  const errorOccurred = (details: browser.webRequest._OnErrorOccurredDetails) =>
    errorOccurredListener(details);
  const completed = (details: browser.webRequest._OnCompletedDetails) =>
    completedListener(details);

  // Add new listeners first, then remove the old ones
  browser.webRequest.onBeforeRequest.addListener(before, { urls }, [
    "blocking",
  ]);
  browser.webRequest.onBeforeSendHeaders.addListener(
    beforeHeaders,
    { urls, types: ["script"] },
    ["blocking", "requestHeaders"],
  );
  browser.webRequest.onHeadersReceived.addListener(headers, { urls }, [
    "blocking",
    "responseHeaders",
  ]);
  browser.webRequest.onErrorOccurred.addListener(errorOccurred, { urls });
  browser.webRequest.onCompleted.addListener(completed, { urls });

  const previous = currentListeners;
  currentListeners = {
    before,
    beforeHeaders,
    headers,
    errorOccurred,
    completed,
  };
  removeListeners(previous);

  // Look up existing content scripts and add the ones that are missing
  const registeredFqdns = (
    await browser.scripting.getRegisteredContentScripts()
  ).map((script) => script.id);
  const newFqdns = fqdns.filter((fqdn) => {
    return !registeredFqdns.includes(fqdn);
  });
  await browser.scripting.registerContentScripts(
    newFqdns.map((fqdn) => {
      return {
        id: fqdn,
        js: ["dist/hooks/content.js"],
        matches: buildUrlPatterns([fqdn]),
        matchOriginAsFallback: true,
        allFrames: true,
        runAt: "document_start",
      };
    }),
  );
  // Remove the content scripts whose fqdn is no longer enrolled
  await browser.scripting.unregisterContentScripts({
    ids: registeredFqdns.filter((fqdn) => !fqdns.includes(fqdn)),
  });

  await clearBrowserCaches(newFqdns);

  console.log(
    `[webcat] installEnrolledListeners: registered listeners for ${fqdns.length} FQDN(s)`,
  );
}
