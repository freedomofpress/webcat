import { endpoint } from "../config";
import { db, origins, tabs } from "../globals";
import { metadataRequestSource } from "./interfaces/base";
import { WebcatError } from "./interfaces/errors";
import { logger } from "./logger";
import { validateOrigin } from "./request";
import { FRAME_TYPES } from "./resources";
import { validateResponseContent, validateResponseHeaders } from "./response";
import { errorpage } from "./ui";
import { initializeScheduledUpdates, retryUpdateIfFailed } from "./update";
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
  // Initial list download here
  // We probably want do download the most recent list, verify signature and log inclusion
  // Then index persistently in indexeddb. We do this at every startup anyway, so there is no reason for
  // not just calling the startup listener
  await startupListener();
}

export async function startupListener() {
  console.log("[webcat] Running startupListener");

  // Run the list updater
  await initializeScheduledUpdates(db, endpoint);
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
      `Error when parsing response headers: ${result}`,
      details.tabId,
      fqdn,
    );
    origins.delete(fqdn);
    tabs.delete(details.tabId);
    errorpage(details.tabId, result);
    return { cancel: true };
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
