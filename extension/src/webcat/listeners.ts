import { endpoint } from "../config";
import { db, origins, tabs } from "../globals";
import { getHooks } from "./genhooks";
import { hooksType, metadataRequestSource } from "./interfaces/base";
import { WebcatError } from "./interfaces/errors";
import { logger } from "./logger";
import { validateOrigin } from "./request";
import { FRAME_TYPES } from "./resources";
import { validateResponseContent, validateResponseHeaders } from "./response";
import { errorpage } from "./ui";
import { retryUpdateIfFailed } from "./update";
import { getFQDN, isExtensionRequest } from "./utils";

function cleanup(tabId: number) {
  if (tabs.has(tabId)) {
    const fqdn = tabs.get(tabId);
    /* DEVELOPMENT GUARDS */
    /* It's not possible that we have reference for a object that does not exists */
    if (!fqdn) {
      throw new Error(
        "When deleting a tab, we found an enrolled tab with fqdn",
      );
    }
    const originState = origins.get(fqdn);
    if (!originState) {
      throw new Error(
        "When deleting a tab, we found an enrolled tab with no associated originState",
      );
    }
    /* END */
    originState.current.references--;
    tabs.delete(tabId);
  }
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

export function tabCloseListener(
  tabId: number,
  //removeInfo?: browser.tabs._OnRemovedRemoveInfo,
) {
  cleanup(tabId);
}

export async function headersListener(
  details: browser.webRequest._OnHeadersReceivedDetails,
): Promise<browser.webRequest.BlockingResponse> {
  // Skip allowed types, etensions request, and not enrolled tabs
  const fqdn = getFQDN(details.url);

  if (
    // Skip non-enrolled tabs
    (!tabs.has(details.tabId) &&
      details.tabId > 0 &&
      (await db.getFQDNEnrollment(fqdn)).length === 0) ||
    // Skip non-enrolled workers
    (details.tabId < 0 && (await db.getFQDNEnrollment(fqdn)).length === 0) ||
    isExtensionRequest(details)
  ) {
    // This is too much noise to really log
    //console.debug(`headersListener: skipping ${details.url}`);
    return {};
  }

  // We checked for enrollment back when the request was fired
  // For tabs only we could do this, but for workers nope
  //const fqdn = tabs.get(details.tabId);
  // So instead let's get that again

  if (!origins.has(fqdn)) {
    // We are dealing with a background request, probably a serviceworker
    logger.addLog(
      "info",
      `Loading metadata for a background request to ${fqdn}`,
      details.tabId,
      fqdn,
    );
    const result = await validateOrigin(
      fqdn,
      details.url,
      details.tabId,
      metadataRequestSource.worker,
    );
    if (result instanceof WebcatError) {
      origins.delete(fqdn);
      tabs.delete(details.tabId);
      errorpage(details.tabId, result);
      return { cancel: true };
    }
  }

  const originStateHolder = origins.get(fqdn);

  if (!originStateHolder) {
    throw new Error("No originState while starting to parse response.");
  }

  const result = await validateResponseHeaders(originStateHolder, details);
  if (result instanceof WebcatError) {
    logger.addLog(
      "error",
      `Error when parsing response headers: ${result}: ${result.details?.join(", ")}`,
      details.tabId,
      fqdn,
    );
    origins.delete(fqdn);
    tabs.delete(details.tabId);
    errorpage(details.tabId, result);
    return { cancel: true };
  }

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
    const hooks_key = originStateHolder.current.hooks_key;

    const listener = async (
      navDetails: browser.webNavigation._OnCommittedDetails,
    ) => {
      if (navDetails.tabId !== details.tabId) return;
      if (navDetails.frameId !== details.frameId) return;

      browser.webNavigation.onCommitted.removeListener(listener);

      await browser.tabs.executeScript(details.tabId, {
        code: getHooks(hooksType.content_script, wasm, hooks_key),
        runAt: "document_start",
        frameId: details.frameId,
      });
    };

    browser.webNavigation.onCommitted.addListener(listener);
  }

  return {};
}

export async function requestListener(
  details: browser.webRequest._OnBeforeRequestDetails,
): Promise<browser.webRequest.BlockingResponse> {
  const fqdn = getFQDN(details.url);

  if (
    (details.tabId < 0 && !origins.has(fqdn)) ||
    isExtensionRequest(details)
  ) {
    // TODO: is this still relevant? it seems like it
    // should apply to workers (no tab id) if they do
    // a fetch request and the origin doesn't exists
    // To be safe maybe we should check for enrollment again?
    return {};
  }

  // TODO: why does this happen for sub_frames?
  //if (details.type === "main_frame" || details.type === "sub_frame") {
  if (FRAME_TYPES.includes(details.type)) {
    // User is navigatin to a new context, whether is enrolled or not better to reset
    cleanup(details.tabId);

    logger.addLog(
      "info",
      `Loading ${details.type} ${details.url}`,
      details.tabId,
      fqdn,
    );

    await retryUpdateIfFailed(db, endpoint);

    const result = await validateOrigin(
      fqdn,
      details.url,
      details.tabId,
      metadataRequestSource.main_frame,
    );
    if (result instanceof WebcatError) {
      origins.delete(fqdn);
      tabs.delete(details.tabId);
      errorpage(details.tabId, result);
      return { cancel: true };
    }
    if (result) {
      logger.addLog("info", `Redirecting to https`, details.tabId, fqdn);
      return result;
    }
  }

  /* DEVELOPMENT GUARD */
  /*it's here for development: meaning if we reach this stage
    and the fqdn is enrolled, but a entry in the origin map has nor been created, there is a critical security bug */
  if ((await db.getFQDNEnrollment(fqdn)).length !== 0 && !origins.has(fqdn)) {
    console.error(
      "FATAL: loading from an enrolled origin but the state does not exists.",
    );
    return { cancel: true };
  }
  /* END */

  // if we know the tab is enrolled, or it is a worker background connction then we should verify
  if (tabs.has(details.tabId) === true || details.tabId < 0) {
    await validateResponseContent(details);
  }

  // See https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/BlockingResponse
  // Returning a response here is a very powerful tool, let's think about it later
  return {};
}
